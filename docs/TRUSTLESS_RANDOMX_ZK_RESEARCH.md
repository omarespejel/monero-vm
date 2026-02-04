# Trustless Monero Verification (Raito-Style) — Research Notes

## Goal

Design a trustless, ZK-based verifier for Monero events on Starknet, analogous
to Raito’s trustless Bitcoin verification, but for Monero’s PoW and private
transactions.

This document focuses on the hardest component: proving RandomX PoW in ZK with a
verifier suitable for Starknet.

## Why this is harder than Raito (Bitcoin)

- Bitcoin PoW is SHA-256 — fast and ZK-friendly.
- Monero PoW is RandomX — randomized VM execution plus large memory.
- Monero transaction validity includes RingCT + Bulletproofs + key images.

Trustless Monero verification therefore requires both PoW correctness and
transaction validity proofs, which are much heavier than Bitcoin’s model.

## RandomX facts that matter for ZK

- RandomX uses randomized programs executed in a VM.
- It is intentionally memory-hard.
- Typical parameters:
  - Dataset size: ~2 GiB.
  - Cache size (light mode): ~256 MiB.
- Light-mode verification uses cache only, but is still memory heavy and slow.
- Core parameters (defaults):
  - `RANDOMX_PROGRAM_SIZE = 256`, `RANDOMX_PROGRAM_ITERATIONS = 2048`,
    `RANDOMX_PROGRAM_COUNT = 8`
  - Scratchpad L3/L2/L1 = 2 MiB / 256 KiB / 16 KiB
  - Cache accesses per Dataset item = 8

## Research status

- No known production ZK circuits for RandomX exist.
- No known end-to-end ZK proof systems exist for full Monero validity.
- A trustless path is possible in principle, but requires original research.

## Best current proof-system fit

**STWO (S-two) prover** is the recommended production-grade prover:
- Production-ready on Starknet mainnet (per auditor).
- Cairo-compatible execution model (Cairo0).
- Onchain verifier available via `stwo-cairo`.

Other zkVMs (Risc0, SP1, Nexus) can execute general programs, but onchain
verification on Starknet would require additional verification bridges.

## Proposed research approach (hard part first)

### Step 1 — Formal proof statement

Define a minimal statement for PoW correctness:
1. Given a Monero block header `H` and difficulty target `T`,
2. RandomX key `K` is derived from `H` per Monero consensus rules,
3. RandomX hash `R = RandomX(K, H)` is correctly computed,
4. `R < T`.

This excludes RingCT initially so we can measure PoW feasibility.

### Step 1b — Production-grade statement (PoW only)

The production-grade PoW proof should additionally bind:
- The exact RandomX parameters (cache size, program sizes, iterations).
- The cache initialization (Argon2d) for key `K`.
- The cache commitment (root) and all memory reads/writes.

This prevents weakened configurations or malformed cache shortcuts.

### Step 1c — Auditor-confirmed constraints

- Use STWO + Cairo0 proving pipeline.
- Use Merkle tree commitments for cache, Poseidon hash preferred.
- Use LogUp-style memory checks for authenticated reads/writes.
- Treat light-mode as security-equivalent to full dataset, but bind cache
  generation (Argon2d) and parameters into the proof.

### Step 2 — Minimal RandomX proof-of-execution

Implement RandomX VM execution in a ZK-friendly VM and generate a proof for a
single hash. Options:
- Cairo0 program + STWO prover.
- RISC-V program + zkVM (if bridgeable to Starknet later).

Focus on **light-mode** to avoid 2 GiB dataset, but note it is still large.

### Step 3 — Memory model design

RandomX’s memory access pattern is the main bottleneck. Research needs:
- Merkleized memory with authenticated reads/writes.
- Efficient memory check arguments to reduce constraint cost.
- Cache commitments for the Argon2-based initialization.

Key constraint: RandomX light-mode still requires ~256 MiB cache. Memory proving
dominates cost. The design must prioritize efficient authenticated memory.

### Step 4 — Cost model

Quantify:
- Prover time
- Proof size
- Verifier constraints in Cairo

This feasibility analysis is paper-worthy even without full deployment.

## Production-grade approach (recommended)

This is the most credible production-grade path to a trustless PoW verifier:

1. **Proof system**: STARK prover (STWO) generating proofs of RandomX execution.
2. **Program**: Cairo0 implementation of RandomX light-mode verifier.
3. **Memory**: Merkleized cache with authenticated reads/writes.
4. **Public inputs**:
   - Block header `H`
   - Difficulty target `T`
   - Cache root commitment
   - RandomX parameters (fixed constants)
5. **Verifier**:
   - Onchain verifier for STWO proofs in Starknet.
   - Check `R < T` inside proof, not onchain.

This avoids external trusted relayers and aligns with a Raito-style model.

## Feasibility risks (must be addressed)

- **Memory proving cost**: 256 MiB cache is the dominant bottleneck.
- **Argon2d initialization**: must be included or proven by commitment.
- **Floating point ops**: RandomX uses IEEE-754; proof circuit must match.
- **Proof size / verifier cost**: must fit Starknet constraints.

If any of these are infeasible, a full trustless path may be blocked.

## Floating point strategy (auditor input)

This is the hardest technical challenge.

Recommended sequence:
1. Start with fixed-point emulation and prove equivalence within RandomX's
   constrained float domain (masked exponent bits in group E registers).
2. If equivalence cannot be proven cleanly, design explicit IEEE-754 constraints
   for double precision and measure constraint cost.

Avoid lookup-table approaches unless the table size is proven feasible.

## Paper-ready contribution candidate

“Feasibility of ZK proofs for RandomX PoW:
memory-check construction, cost model, and preliminary benchmarks.”

This isolates the hardest component and produces a defensible research
contribution even before full Monero validation is possible.

## Next milestones

1. Write a formal proof statement (PoW only).
2. Implement RandomX light-mode VM in Cairo0.
3. Generate a STARK proof for a single block header.
4. Publish feasibility numbers and bottlenecks.
5. Iterate on memory optimization and scale estimates.

## Immediate execution plan (what to build now)

1. **Spec extraction**:
   - Implement a Cairo0-compatible RandomX light-mode interpreter.
   - Use the official RandomX spec for instruction set and VM rules.
2. **Cache commitment**:
   - Merkleize cache and design authenticated read/write interface.
3. **Single-hash proof**:
   - Prove a single `RandomX(K, H)` execution.
   - Output `R` and enforce `R < T` inside the proof.
4. **Benchmarking**:
   - Measure proof time, proof size, and verification cost.
   - Identify memory constraints as the primary bottleneck.

## Benchmark results (synthetic depth-22)

Depth-22 corresponds to ~4M cache items (256 MiB / 64 bytes per item).

Current Cairo gas baselines (snforge):
- Depth-2 × 8 proof checks: ~273k L2 gas
- Depth-22 × 8 proof checks: ~2.04M L2 gas

These are synthetic proofs but representative because verification cost scales
linearly with proof length in OpenZeppelin’s `process_proof`.

Additional edge-case tests added:
- Empty proof where `leaf == root`
- Extended proof (depth-23) against depth-22 root

Full benchmark details: `monero-attestation-verifier/CACHE_LOOKUP_REPORT.md`

## Prototype gate (auditor-recommended)

Before full execution proofs, build a minimal prototype:
- Prove a single authenticated cache lookup under a Merkle root.
- Measure constraint cost for memory authentication.
- Use these measurements to estimate feasibility for full RandomX.

## Longer-term path to full trustless verification

After PoW feasibility:
1. Add chain selection and difficulty rules.
2. Add tx inclusion proofs.
3. Add RingCT + Bulletproofs verification.
4. Add key image uniqueness checks.

Only after these are proven can the system be fully trustless.
