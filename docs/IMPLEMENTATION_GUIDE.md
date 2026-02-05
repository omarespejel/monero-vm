# Monero Event Verification on Starknet

This document describes how to make Starknet contracts verify that a Monero event
actually occurred. It is written as an implementation guide for a new engineer:
start with the near-term, deployable approach that fits the current codebase,
then move toward modern, trust-minimized research paths.

## Scope and goal

Goal: allow the Starknet side of the swap to accept a "Monero event happened"
claim (e.g., a lock transaction reached N confirmations) with strong assurance.

The approaches below are ordered from most deployable to most trust-minimized.

## Key constraints from Monero

Monero is private by design. Verifying a payment is not equivalent to checking a
public address balance, because outputs are stealth addresses and amounts are
hidden (RingCT). A verifier typically needs extra secrets (view key or tx key)
to validate that a specific payment happened.

Important facts from the protocol:

- Monero uses RandomX PoW (since hard-fork 12). RandomX is CPU-optimized and
  memory-hard, which makes on-chain verification expensive.
  Source: Moneropedia RandomX.
- Block validity rules and PoW selection are consensus-critical and change by
  hard-fork version (RandomX from HF12).
  Source: Monero Book, "Blocks".
- Transactions are RingCT with Bulletproof/Bulletproof+ range proofs.
  Source: Monero Book (RingCT), Moneropedia (Bulletproofs).
- A sender can prove a payment with `(txid, recipient address, tx key)`.
  Source: Monero "How to prove a payment was made".

These properties shape what is feasible to verify on Starknet.

## Approach A (deployable now): accountable attestation

This is the recommended first step based on the current repo: keep RPC-based
verification off-chain, but make it accountable on-chain via a quorum of
independent relayers. This reduces trust in any single relayer while avoiding
impractical on-chain PoW or RingCT verification.

### Summary

- Multiple relayers independently verify the Monero event via RPC.
- Each relayer signs a canonical "MoneroEvent" message.
- Starknet contract verifies a threshold of signatures.
- Slashing / removal of relayers is possible if they misbehave.

### Why this fits the current codebase

You already have:

- `watchtower` module with relayer logic
- RPC integration for Monero and Starknet
- A swap registry and health endpoints

Approach A upgrades trust guarantees without rewriting the protocol.

### Detailed design

#### 1) Canonical event schema (off-chain + on-chain)

Define a canonical event structure that is signed by relayers. Field order is
fixed and must be identical across relayers and Cairo.

```
MoneroEventV1 {
  chain_id,          // Starknet chain id (SN_MAIN / SN_SEPOLIA)
  swap_id,           // swap identifier (already in Starknet state)
  txid,              // Monero tx hash (u256, low then high, little-endian)
  output_index,      // which output index in tx
  amount_atomic,     // atomic units
  recipient_view_tag // optional, for output validation
  lock_height,       // block height where tx is included
  confirmations,     // number of confirmations observed
  timestamp,         // block timestamp
  deadline           // expiration for the signature claim
}
```

Notes:
- The schema must be deterministic and versioned.
- Hashing must be domain-separated (e.g., `MONERO_EVENT_V1`).
- Include `deadline` to bound replay risk.

#### 1a) Canonical hashing rules (normative)

- Domain separator: `MONERO_EVENT_V1`.
- Use Poseidon for the canonical event hash.
- Serialize fields in the exact order above.
- For `u256`, append `low` then `high` (little-endian).
- For smaller ints, serialize as felts using standard Cairo `Serde`.
- Hash the serialized felt array with `poseidon_hash_span`.

#### 1b) Signature scheme (normative)

- Use Starknet ECDSA on the Stark curve and built-in verification.
- Public key format and signature layout must be specified and fixed.
- Aggregated signatures are out of scope. Use m-of-n independent signatures.

#### 1c) Replay protection (normative)

On-chain verification must enforce:
- `chain_id` matches the current chain.
- `deadline` has not expired.
- `swap_id` exists and is in the expected state.
- Uniqueness of `(swap_id, txid, output_index)`.

Relayers must sign only after `confirmations >= MIN_CONFIRMATIONS`.

#### 2) Off-chain verification (relayers)

Each relayer:

1. Watches for swap-related txs (Monero daemon or wallet RPC).
2. Extracts `txid`, `output_index`, `amount_atomic`, `block_height`.
3. Verifies `confirmations >= N` (e.g., N=10).
4. Validates the payment proof:
   - If using tx proof: verify `(txid, address, tx key)`.
   - If using view key: scan the output to the recipient address.
5. Constructs `MoneroEventV1` and signs its hash.

What is actually verified off-chain can be tuned:

- Minimal: verify tx exists and is confirmed.
- Stronger: verify tx output belongs to the swap address using tx key or view key.
- Strongest (still off-chain): verify full transaction validity via daemon.

#### 3) On-chain attestation contract

Contract changes (high level):

- Store a set of authorized relayer public keys.
- Store `threshold` (e.g., 3 of 5).
- Accept `MoneroEventV1` + signatures.
- Verify:
  - `threshold` signatures valid.
  - `swap_id` exists and in correct state.
  - `deadline` not expired.
  - `confirmations >= min_confirmations`.
  - `txid` not already used for this swap.
- Emit `MoneroEventAccepted`.

Implementation detail:
Use Starknet ECDSA verification (Stark curve) with built-in verification.

#### 4) Governance and accountability

Add a simple relayer governance mechanism:

- `add_relayer(pubkey)` / `remove_relayer(pubkey)`
- Optional: relayer bonding & slashing (phase 2)
- Emergency pause if quorum is compromised

Minimum slashing conditions:
- Signing invalid events.
- Signing conflicting events for the same `(swap_id, txid, output_index)`.
- Signing with fewer than `MIN_CONFIRMATIONS`.

#### 5) Operational requirements

- At least 3 independent relayers with separate infrastructure.
- Monitoring for reorgs; signatures should be based on confirmations only.
- Audit trail: store signed payloads and evidence in logs.

#### 6) Reorg policy (normative)

Relayers must:
- Require `MIN_CONFIRMATIONS` before signing.
- Re-check the transaction before signing.
- Refuse to sign if the tx is missing or reorged out.

If a reorg occurs after acceptance, it is a governance issue handled by relayer
policy and slashing rules, not on-chain validation.

#### 7) Off-chain evidence (normative)

- Store a hash of proof materials on-chain (optional but recommended).
- Store raw proofs off-chain with a stable reference (hash or URL).

### Security properties

Pros:
- Avoids on-chain PoW / RingCT verification.
- Reduces single-relayer trust (quorum).
- Achievable now.

Cons:
- Still trusts that a quorum is honest.
- Requires governance to manage relayers.

### Implementation checklist (repo mapping)

- `watchtower/`: add multi-relayer signing, canonical event struct.
- `rust/`: add canonical hashing + signing utilities.
- `cairo/`: add a relayer quorum verifier contract module and integrate
  it with the swap flow.
- `docs/`: update protocol spec with trust assumptions and parameters.

### Implementation handoff (attestation verifier build)

Important: this is not a Monero light client. It is an attestation verifier
that checks a quorum of relayer signatures over a canonical event hash.

#### Scope (must follow)

Do not attempt to implement:
- RingCT verification
- Bulletproof verification
- RandomX PoW verification

The on-chain contract only verifies a quorum of relayer signatures over a
canonical event hash.

#### Hard constraints

- No custom cryptography (no custom EC math, hashes, RNG).
- Use audited Cairo libraries only.
- OpenZeppelin Cairo v2.0.0 (pinned in this repo).
- Cairo edition 2024_07.
- All public functions include doc comments and tests.
- After every Cairo edit: run `scarb build`.
- Run `snforge test` before merging and at phase boundaries.

#### Project structure (target)

```
project/
├── Scarb.toml
├── src/
│   ├── lib.cairo
│   └── attestation/
│       ├── event.cairo
│       ├── quorum_verifier.cairo
│       ├── relayer_registry.cairo
│       └── replay_protection.cairo
└── tests/
    ├── test_event.cairo
    ├── test_quorum_verifier.cairo
    ├── test_relayer_registry.cairo
    └── test_replay_protection.cairo
```

#### Phase plan (implementation order)

Phase 1: Attestation foundation
1. Define `MoneroEventV1` in `src/attestation/event.cairo`.
2. Implement `compute_event_hash`:
   - Domain-separated Poseidon hash
   - Use `core::poseidon::poseidon_hash_span`
   - Hash all fields in spec order
3. Tests in `tests/test_event.cairo`:
   - Deterministic hash for known inputs
   - Edge cases: zero and max values

Phase 2: Quorum verifier
1. Create trait + storage in `src/attestation/quorum_verifier.cairo`.
2. Implement:
   - Threshold verification (m-of-n, no aggregation)
   - Signature verification using Starknet ECDSA builtins
3. Tests in `tests/test_quorum_verifier.cairo`:
   - Single signature
   - Threshold success/failure
   - Invalid signature cases

Phase 3: Relayer registry
1. `add_relayer` / `remove_relayer`
2. Use OpenZeppelin access control (Ownable or roles)
3. Tests in `tests/test_relayer_registry.cairo`

Phase 4: Replay protection
1. Store accepted `(swap_id, txid, output_index)` tuples
2. Block duplicates
3. Tests for replay prevention

Phase 5: Event validator (integration)
1. Combine quorum verification + replay protection
2. End-to-end event acceptance flow
3. Integration tests

#### Build & test commands

```bash
cd project && scarb build
cd project && snforge test
```

## Approach B (modern research): light-client proofs

Goal: verify Monero chain validity and tx inclusion on Starknet using succinct
proofs, with minimal trust.

### Core idea

Use a light-client protocol to prove that:

1. A specific Monero block is in the best chain.
2. A transaction is included in that block.

Relevant research:

- FlyClient provides super-light proofs for PoW chains using probabilistic
  sampling and MMR commitments.
  Source: FlyClient (IACR eprint 2019/226).
- Zcash ZIP-221 shows how to modify block headers to embed MMR commitments for
  FlyClient-style proofs.

### Why this is hard for Monero today

Monero does not currently commit an MMR root in block headers. FlyClient requires
MMR commitments or similar chain-history commitments to enable succinct proofs.
Zcash added this via a consensus change (ZIP-221). Monero would need a similar
consensus change or a "velvet fork" approach.

Additional obstacles:

- Verifying RandomX PoW is expensive.
- Light-client proofs are probabilistic and require careful parameter choices.
- On-chain verification still needs a proof system or a bridge-friendly format.

### What a Monero FlyClient-style path would require

1. Consensus change or velvet-fork commitment to an MMR root in Monero headers.
2. A formal FlyClient proof construction for Monero difficulty rules and RandomX.
3. A verifier on Starknet (likely via a SNARK/STARk or Cairo-friendly proof).

This is "modern research" but not yet deployable without consensus changes.

## Approach C (modern research): ZK proofs of Monero validity

Goal: provide a succinct proof that a Monero transaction is valid and confirmed,
without relying on a relayer quorum.

### Proof components

A full proof would need to verify:

1. RandomX PoW for a chain of blocks.
2. Difficulty adjustment / chain selection rules.
3. Transaction inclusion in a block (Merkle proof).
4. Transaction validity:
   - RingCT signature validity.
   - Range proofs (Bulletproof/Bulletproof+).
   - Key image uniqueness, etc.

### Why this is difficult

RingCT + Bulletproofs are complex, and RandomX is memory-hard. Proving these in
ZK is a major research and engineering effort. Even if a SNARK circuit can be
designed, generating proofs may be expensive and verification must be feasible
in Cairo.

This is the most trust-minimized path but requires significant new research and
likely off-chain proof generation infrastructure.

## Hybrid path (pragmatic)

Combine Approach A now, while preparing for Approach B or C later:

- Implement relayer quorum with strong auditability.
- Add an "upgradable verifier" interface in Cairo so the proof system can be
  swapped later (e.g., replace quorum verification with a ZK proof verifier).
- Keep detailed event schemas, canonical hashes, and state transitions stable.

## Privacy implications

If you require on-chain verification that a specific Monero output paid a
recipient, you may need to reveal:

- a transaction key (tx proof), or
- a private view key (for scanning outputs).

Either reveals information about the payment. For atomic swaps, you may accept
this privacy tradeoff because the swap itself is already revealing some linkage.

## Recommended phased roadmap

### Phase 1 (now): quorum attestation

- Implement canonical `MoneroEventV1`.
- Add threshold signature verification in Cairo.
- Update `watchtower` to produce signed event claims.
- Add governance for relayer set.
- Add monitoring and reorg safety checks.

### Phase 2: stronger attestations

- Require each relayer to attach a tx proof (tx key + address).
- Store hashes of proofs on-chain; raw proofs stay off-chain.
- Add dispute windows and slashing conditions.

### Phase 3: research prototypes

- Prototype a FlyClient-style proof format for Monero (off-chain first).
- Prototype RandomX proof systems with ZK or STARKs.
- Evaluate feasibility of a Monero consensus change for MMR commitments.

## Open research questions

- Can a FlyClient-like protocol be applied to Monero without consensus changes?
- Can RandomX be efficiently proven in ZK with acceptable cost?
- What is the minimal proof of Monero tx validity needed for an atomic swap?
- How to preserve privacy while still proving a swap event?

## References

- Monero Book: Blocks and consensus rules
  https://monero-book.cuprate.org/consensus_rules/blocks.html
- Monero Book: RingCT
  https://monero-book.cuprate.org/consensus_rules/transactions/ring_ct.html
- Moneropedia: RandomX
  https://www.getmonero.org/resources/moneropedia/randomx.html
- Moneropedia: Bulletproofs
  https://www.getmonero.org/resources/moneropedia/bulletproofs.html
- Monero payment proof guide
  https://www.getmonero.org/resources/user-guides/prove-payment.html
- FlyClient paper
  https://eprint.iacr.org/2019/226
- Zcash ZIP-221 (FlyClient consensus changes)
  https://zips.z.cash/zip-0221
