# MoneroVM

**Trustless Monero verification on Starknet via fraud proofs.**

## What This Solves

| Problem | Solution | Status |
|---------|----------|--------|
| **Liveness Failures** | MoneroVM fraud proofs | ✅ 464 tests |
| **Light Client** | RandomX verification on-chain | ✅ Fraud proof MVP |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              Monero Verification on Starknet                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  CLAIMED EXECUTION                    MONEROVM (CHALLENGE)      │
│  ┌────────────────────────┐          ┌────────────────────────┐ │
│  │ • Off-chain RandomX    │          │ • RandomX verification │ │
│  │ • State commitments    │   ──►    │ • Fraud proofs         │ │
│  │ • Merkle roots         │  challenged │ • Trustless recovery │ │
│  └────────────────────────┘          └────────────────────────┘ │
│         cheap upfront                 Only when needed          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**When is MoneroVM needed?** When a RandomX execution claim is disputed and the chain needs to resolve it on-chain.

## Why Fraud Proofs (Not Pure ZK)?

**Research Finding**: Pure ZK verification of RandomX is **economically impractical**.
- ~6.26B Sierra gas per hash (~$600-1000 USD)
- 10-15 minute prover time
- Technically possible but not viable for production

**MoneroVM's Solution**: BitVM-inspired optimistic verification
- Attestation for normal flow (fast, cheap)
- Fraud proofs as trustless fallback (disputed cases only)
- Similar to Arbitrum/Optimism's approach to L2 scaling

See [docs/ROADMAP.md](docs/ROADMAP.md) for full roadmap.

### ZK Feasibility Analysis (Auditor's Final Assessment)

| Criterion | Status | Value |
|-----------|--------|-------|
| Sierra Gas/hash | 🔴 POOR | **~6.26B** |
| Prover time | 🔴 HIGH RISK | **10-15 min/hash** |
| Memory | ✅ OK | S-two handles it |
| Technical feasibility | ⚠️ MARGINAL | Possible but impractical |

**Cost Breakdown**:
| Component | Sierra Gas |
|-----------|------------|
| Cairo Steps (~50M) | 5B |
| FP Operations (~1.5M) | 750M |
| Poseidon/Merkle (~500K) | 245M |
| MUL_MOD (~200K) | 121M |
| Range Checks (~2M) | 140M |
| **TOTAL** | **~6.26B** |

> **Auditor's Verdict**: "Pure ZK verification of RandomX is technically possible but
> economically impractical. Fraud proofs are strongly recommended."

See [docs/FLOATING_POINT_RESEARCH.md](docs/FLOATING_POINT_RESEARCH.md) for full research.

## Components

### Fraud Proof System (Primary)
- **State Commitment**: Poseidon-based VM state hashing
- **Instruction Verifiers**: 14 integer + 5 memory operations
- **PRT Security**: Permissionless Refereed Tournament (anti-collusion)
- **Bisection Protocol**: 8-round instruction-level isolation

### RandomX Implementation
- **SuperscalarHash**: Program generation and execution (14 instruction types)
- **Blake2bGenerator**: PRNG for deterministic program generation
- **Cache Commitment**: Merkle proof verification for cache lookups
- **AesHash1R/AesGenerator1R**: Single-round AES operations

## CI and release gate

| Tier | Command / step | When |
|------|-----------------|------|
| **Fast (default CI)** | `scarb test` | Every PR; 464 tests, ~1–2 min. |
| **Release-grade** | `scarb test` + full FP vector pipeline | Pre-release; run `tools/run_fp_vector_pipeline.sh` (see [FP vectors](#floating-point-test-vectors) below). |
| **Optional** | OpenCL cross-validation | If you gate a release on external consistency. |

Fast tier green = **464 passed, 0 failed** with `snforge` is the main signal for default CI.

## Status

| Component | Status | Tests |
|-----------|--------|-------|
| **Challenge Contract** | ✅ Complete | 14 |
| **Fraud Proof: State Commitment** | ✅ Complete | 10 |
| **Fraud Proof: Integer Verifiers** | ✅ Complete | 13 |
| **Fraud Proof: Memory Verifiers** | ✅ Complete | 7 |
| **Fraud Proof: PRT Bisection** | ✅ Complete | 7 |
| **Fraud Proof: ISTORE** | ✅ Complete | Struct |
| **Fraud Proof: FP Stubs** | ✅ Complete | 9 |
| **Fraud Proof: CBRANCH** | ✅ Complete | 5 |
| SuperscalarHash execution | ✅ Complete | 78 |
| Instruction set (14 types) | ✅ Complete | Covered |
| Cache commitment (Merkle) | ✅ Complete | 19 |
| Blake2bGenerator | ✅ Complete | 21 |
| Dataset item generation | ✅ Complete | 12 |
| AesHash1R / AesGenerator1R | ✅ Complete | 32 |
| PoW verification pipeline | ✅ Complete | 6 |
| Quorum verification | 💤 Preserved | Attestation path |

**Total: 464 tests passing** (including 126 fraud proof tests w/ IEEE-754 + auditor fixes + 14 challenge contract tests)

### Instruction Verifier Gas Costs (L2 Gas)

Measured from snforge test output:

| Verifier Type | L2 Gas | Cost Category |
|---------------|--------|---------------|
| IADD_R, ISUB_R | ~16K | Low |
| IMUL_R, IMULH_R | ~20K | Low |
| CBRANCH | ~40K | Low |
| IROR_R, IROL_R | ~335K | Medium |
| Memory + Merkle (IADD_M, etc.) | ~387K | Medium |
| State Hash (Poseidon) | ~403K | Medium |

**Dispute Resolution Cost**: ~787K L2 gas total (pre-state hash + verify instruction + post-state hash)

### Security-Critical: Merkle Proof Verification ✅
- Dataset item count: 34,078,720 items
- Merkle tree depth: 25 levels
- Poseidon hash for zkSNARK efficiency
- 19 security tests for proof validation

### AesHash1R Implementation ✅
- Full AES S-box and inverse S-box
- GF(2^8) multiplication for MixColumns
- ShiftRows, SubBytes, MixColumns transformations
- Single-round AES encrypt/decrypt per RandomX spec
- Finalization with extra keys (xkey0, xkey1)
- 18 tests for correctness and determinism

### AesGenerator1R Implementation ✅
- PRNG using single AES rounds
- Round keys from Hash512("RandomX AesGenerator1R keys")
- Column 0,2: decrypt; Column 1,3: encrypt
- 14 tests including official test vector

### E2E Verification Framework ✅
- Complete verification pipeline structure
- Cache Merkle proof verification (8 proofs per Dataset item)
- Difficulty target comparison
- Official test vectors documented (5 E2E hashes)
- 15 tests for verification logic

### Instruction-Level Test Vectors ✅

All arithmetic operations produce **bit-perfect results** matching the official C++ implementation:

| Instruction | Operation | Status | Notes |
|-------------|-----------|--------|-------|
| IMUL_R | 64-bit multiply low | ✅ Exact | Native u64 |
| IMULH_R | Unsigned multiply high | ✅ Exact | u128 → high 64 |
| ISMULH_R | Signed multiply high | ✅ Exact | Unsigned + sign handling |
| ISUB_R | Subtract with wrap | ✅ Exact | Wrapping arithmetic |
| IROR_R | Rotate right | ✅ Exact | Shift + OR |
| IROL_R | Rotate left | ✅ Exact | Shift + OR |

**ISMULH_R Implementation Note**: Uses unsigned arithmetic with manual sign handling to avoid
Cairo `i128` division quirks. Edge cases verified: INT64_MIN × INT64_MIN, INT64_MAX × INT64_MIN.
See [docs/SECURITY_AUDIT_NOTES.md](docs/SECURITY_AUDIT_NOTES.md) for details.

### Official Test Vectors from tests.cpp (COMPLETE)
- Reciprocal: 7/7 verified ✅
- IMULH_R/ISMULH_R: Official vectors ✅
- Dataset items: 4/4 documented ✅
- E2E hash vectors: 5/5 documented ✅ (includes hex mining block)
- Cache memory vectors: 3/3 documented ✅
- SuperscalarHash program hashes: 10/10 documented ✅
- AesGenerator1R: 1/1 documented ✅
- Commitment: 1/1 documented ✅

## Implementation Decisions

### Blake2bGenerator (PRNG)

**Decision**: Adapt Herodotus/integrity Blake2s to Blake2b

**Reference**: [HerodotusDev/integrity](https://github.com/HerodotusDev/integrity)
- Path: `src/common/blake2s.cairo`
- Audit: zksecurity.pdf in `/audit` folder
- License: Apache-2.0

**Adaptations required**:
- Word size: 32-bit → 64-bit
- Rounds: 10 → 12
- Rotations: (16,12,8,7) → (32,24,16,63)

**Source of truth**: [RFC 7693](https://datatracker.ietf.org/doc/html/rfc7693)

### IMUL_RCP (Reciprocal Calculation)

**Decision**: Compute on-the-fly (not index-based)

**Rationale**:
- Simpler witness (no reciprocal table correctness proof)
- Self-contained verification (each instruction independently verifiable)
- Gas cost acceptable (~50 operations, executed ~8-16 times per program)

### Decoder Buffer Selection

**Decision**: Witness selection initially, prove later if needed

**Rationale**:
- Programs are deterministically generated from seed
- If final program matches, intermediate selections were correct
- Can upgrade to full proof verification later

### Test Vectors

**Decision**: Extract from RandomX reference implementation first

**Source**: [tevador/RandomX](https://github.com/tevador/RandomX)
- Build with `TRACE=1` for intermediate values
- Required vectors:
  - Blake2Generator output for `"test key 000"` (first 1024 bytes)
  - First 3 generated programs (instruction dump)
  - Dataset item 0 intermediate states

### FP Trace Pipeline (M2)

We now generate FP vectors directly from the RandomX reference interpreter.
- Trace output: `tools/fp_trace.jsonl`
- Generator: `tools/generate_fp_vectors.py`
- Cairo vectors (generated, not committed): `tests/test_fp_vectors.cairo`
- Runner: `tools/run_fp_vector_pipeline.sh`
 - Per-opcode split: `tools/split_fp_trace.py` → `test_vectors/`
 - Optional OpenCL cross-check: `tools/run_opencl_validation.sh`
See `docs/FP_TRACE_PIPELINE.md` for details.

Canonical audit vectors are checked in under `tests/vectors/canonical/`
and exercised by `tests/test_fp_vectors_canonical.cairo`.

The vector file is intentionally generated on demand (it can be ~1.9GB), so
default tests stay fast. To run the full vector suite:

```
tools/run_fp_vector_pipeline.sh
scarb test
```


## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Dataset Item Generation                   │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │ Blake2b      │───▶│ SuperscalarHash │───▶│ Cache XOR   │   │
│  │ Generator    │    │ Program Gen  │    │ (8 accesses) │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  Constants: superscalarMul0, superscalarAdd1-7              │
│  Iterations: 8 programs per dataset item                    │
│  Output: 64 bytes (8 × u64 registers)                       │
└─────────────────────────────────────────────────────────────┘
```

## Key Constants

```cairo
// Blake2b IV (RFC 7693)
const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
];

// SuperscalarHash constants
const SUPERSCALAR_MUL0: u64 = 6364136223846793005;
const SUPERSCALAR_ADD1: u64 = 9298411001130361340;
// ... (see prototype.cairo for full list)

// RandomX parameters
const RANDOMX_SUPERSCALAR_LATENCY: u32 = 170;
const RANDOMX_CACHE_ACCESSES: u32 = 8;
const SUPERSCALAR_MAX_SIZE: u32 = 512;
const LOOK_FORWARD_CYCLES: u32 = 4;
const MAX_THROWAWAY_COUNT: u32 = 256;
```

## Security & Audits

The RandomX reference implementation has been audited by two independent security firms:

| Audit | Date | Result |
|-------|------|--------|
| [X41 D-Sec](https://x41-dsec.de/static/reports/X41-RandomX-Audit-2019-Final-Report-Public.pdf) | June 2019 | 0 critical, 4 medium (all config-dependent) |
| [OSTIF/Kudelski](https://ostif.org/wp-content/uploads/2019/08/Report-Kudelski-201907022.pdf) | July 2019 | Cryptographic design validated |

**Key findings applied to this implementation:**

1. **Bit-perfect matching required** - Hash verification has zero tolerance for approximations
2. **Avalanche effect** - Single bit error cascades to completely different hash
3. **`smulh` implementation sound** - Reference code reviewed, no issues found
4. **Default parameters safe** - All medium vulnerabilities require non-standard config

See [docs/SECURITY_AUDIT_NOTES.md](docs/SECURITY_AUDIT_NOTES.md) for detailed findings, edge cases,
and implementation learnings (including the ISMULH_R fix).

## References

- [RandomX Specification](https://github.com/tevador/RandomX/blob/master/doc/specs.md)
- [RFC 7693 - Blake2](https://datatracker.ietf.org/doc/html/rfc7693)
- [Herodotus/integrity](https://github.com/HerodotusDev/integrity) - Audited Blake2s
- [STWO Blake2 Examples](https://github.com/starkware-libs/stwo/tree/dev/crates/examples/src/blake)

## Build

```bash
scarb build
snforge test
```

## License

Apache-2.0
# monero-vm
