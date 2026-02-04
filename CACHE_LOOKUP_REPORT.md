# Authenticated Cache Lookup Benchmark (Synthetic)

## Scope

Measure the cost of authenticated cache lookup using OpenZeppelin's audited
Merkle proof verifier with Poseidon hashing. This is the prototype gate before
full RandomX execution proofs.

## Method

We benchmark Merkle proof verification using synthetic proofs, because the
OpenZeppelin verifier is depth-agnostic and costs scale linearly with proof
length.

- Hash function: Poseidon (commutative) via `PoseidonCHasher::commutative_hash`
- Leaf hashing: domain-separated `LEAF_DOMAIN || value`
- Proof depths:
  - Depth-2 (sanity, 2 siblings)
  - Depth-22 (production proxy, 22 siblings)
- Repetitions: 8 proof verifications per test

## Implementation

Verification function:
```1:7:monero-randomx-verifier/src/randomx/cache_commitment.cairo
/// Verifies a Merkle proof for a cache leaf under the given root.
/// This is the prototype gate: authenticated cache lookup.
pub fn verify_cache_leaf(root: felt252, leaf: felt252, proof: Span<felt252>) -> bool {
    use openzeppelin_merkle_tree::merkle_proof;

    merkle_proof::verify_poseidon(proof, root, leaf)
}
```

Benchmark + tests:
```1:179:monero-randomx-verifier/tests/test_cache_commitment.cairo
// See test_cache_commitment.cairo for:
// - depth-2 benchmark
// - depth-22 benchmark
// - negative tests (wrong leaf/sibling, truncated, extended)
// - empty proof case
```

## Results (snforge test)

Gas baselines (L2 gas):
- Depth-2 ×8: ~273,286
- Depth-22 ×8: ~2,038,558

Approximate per-proof cost:
- Depth-2: ~34k
- Depth-22: ~255k

Edge-case validations:
- Empty proof (leaf == root): ~25,652
- Wrong leaf: ~479,012
- Wrong sibling: ~475,660
- Truncated proof: ~465,548
- Extended proof: ~485,772

Note: these negative tests are expected to fail verification but still incur
similar per-proof costs due to full hash evaluation.

## Observations

- Verification cost scales linearly with proof length as expected.
- Depth-22 ×8 is a production proxy for 4M cache items (2^22 leaves).
- Domain separation prevents node-as-leaf collisions.

## Projected Full Pipeline Gas Budget (Estimate)

| Component | Per-Hash Cost | Notes |
|-----------|--------------|-------|
| Cache lookup (×8 per hash) | ~2.0M gas | 8 authenticated reads at depth-22 |
| RandomX VM execution | TBD | Pending prototype |
| Dataset lookup (×64 per hash) | TBD | 64 reads from 2 GiB dataset |
| Floating-point emulation | TBD | IEEE-754 soft-float |
| **Total per RandomX hash** | **TBD** | Target: feasible for on-chain verification |

## Limitations

- Proofs are synthetic (not derived from a real 2^22 tree).
- This benchmark measures verifier cost only; does not include:
  - RandomX VM execution
  - Argon2d cache construction proof
  - Floating-point emulation

## Next Step

Proceed to the single authenticated cache lookup report review with auditor
approval, then begin the single RandomX hash prototype.
