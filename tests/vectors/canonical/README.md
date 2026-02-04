# Canonical FP Vectors (Audit Baseline)

These vectors are a **small, canonical baseline** checked into git for audit reproducibility.
They are **not** the full RandomX trace corpus. Full vectors are generated on demand via
`tools/run_fp_vector_pipeline.sh` and are intentionally excluded from git due to size.

## Provenance
- Derived from RandomX IEEE-754 semantics and verified against our Cairo verifier.
- Intended to cover critical FP edge cases (zero, signed zero, near-zero divisors, and
  rounding-mode transitions). 

## Usage
- These vectors are referenced by tests in `monero-vm/tests/test_fp_vectors_canonical.cairo`.
- Full vectors are generated separately and used for release gating.

## Files
- `fp_fdiv.json` — small FDIV edge-case set (near-zero divisors, zero dividend, self-division)
- `fp_fadd.json` — signed-zero rounding edge cases
