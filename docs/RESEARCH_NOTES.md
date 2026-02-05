# MoneroVM: Research Notes

This document consolidates research findings on ZK feasibility and floating-point verification for RandomX.

---

## Executive Summary

**Conclusion**: Pure ZK verification of RandomX is economically impractical (~6.26B Sierra gas, ~$626/hash). MoneroVM uses fraud proofs instead, achieving ~787K gas per dispute.

---

## 1. Why RandomX is Hard to Verify

### Comparison with Bitcoin (Raito-style)

| Aspect | Bitcoin | Monero |
|--------|---------|--------|
| PoW Algorithm | SHA-256 | RandomX |
| ZK-Friendliness | High | Low |
| Memory Requirement | None | 256MB cache |
| Instruction Set | Fixed hash | 29-instruction VM |
| Floating Point | None | IEEE-754 with 4 rounding modes |

### RandomX Architecture

- **VM-based execution**: Randomized programs executed on a custom VM
- **Memory-hard**: 2MB scratchpad + 256MB cache (light mode)
- **Core parameters**:
  - `RANDOMX_PROGRAM_SIZE = 256`
  - `RANDOMX_PROGRAM_ITERATIONS = 2048`
  - `RANDOMX_PROGRAM_COUNT = 8`
  - Scratchpad: L3=2MB, L2=256KB, L1=16KB

---

## 2. ZK Feasibility Analysis

### Cost Model (Final Assessment)

| Component | Count | Gas/Op | Total Gas |
|-----------|-------|--------|-----------|
| Cairo Steps (VM) | ~50M | 100 | 5.0B |
| FP Operations | ~1.5M | ~500 | 750M |
| Poseidon (Merkle) | ~500K | 491 | 245M |
| MUL_MOD (64-bit) | ~200K | 604 | 121M |
| Range Checks | ~2M | 70 | 140M |
| **TOTAL** | | | **~6.26B** |

**Prover Time**: 10-15 minutes per hash (unacceptable for production)

**Verdict**: Pure ZK is technically possible but economically impractical.

### Go/No-Go Assessment

| Criterion | Status | Notes |
|-----------|--------|-------|
| Technical Feasibility | MARGINAL | Possible but expensive |
| Prover Time | HIGH RISK | 10-15 min/hash |
| Memory | OK | STWO handles large workloads |
| Cost Efficiency | POOR | ~$626/hash |
| **Fraud Proof Alternative** | **VIABLE** | **Recommended** |

---

## 3. Floating-Point Research

### FP Instructions in RandomX (9 total, ~36.7% of VM)

| Instruction | Operation | Description |
|-------------|-----------|-------------|
| FADD_R | dst = dst + src | Add register to register |
| FADD_M | dst = dst + [mem] | Add memory to register |
| FSUB_R | dst = dst - src | Subtract register from register |
| FSUB_M | dst = dst - [mem] | Subtract memory from register |
| FMUL_R | dst = dst * src | Multiply register by register |
| FDIV_M | dst = dst / [mem] | Divide register by memory |
| FSQRT_R | dst = sqrt(dst) | Square root |
| FSCAL_R | XOR mask | Scale by power of 2 |
| CFROUND | fprc = bits | Set rounding mode |

### Rounding Modes (FPRC register)

| fprc | IEEE-754 Mode | Behavior |
|------|---------------|----------|
| 0 | roundTiesToEven | Round to nearest, ties to even |
| 1 | roundTowardNegative | Always round toward -∞ |
| 2 | roundTowardPositive | Always round toward +∞ |
| 3 | roundTowardZero | Truncate toward zero |

### Register Groups

| Group | Registers | Exponent Range | Notes |
|-------|-----------|----------------|-------|
| **F** | f0-f3 | Full IEEE-754 | Additive operations |
| **E** | e0-e3 | Constrained (2^-240 to 2^240) | Multiplicative operations |

### Prior Art Analysis

#### ZKLP (2024) - LIMITED APPLICABILITY

**Source**: [arxiv.org/abs/2404.14983](https://arxiv.org/abs/2404.14983)

| Claim | Reality |
|-------|---------|
| "64 constraints per FP mult" | Misleading - amortized over 2^15 ops |
| IEEE-754 compliant | Only roundTiesToEven - missing 3 modes |
| Directly portable | No - gnark (BN254) vs Cairo (M31) |

#### Noir IEEE-754 (2024) - REFERENCE

**Source**: [github.com/jeswr/noir_IEEE754](https://github.com/jeswr/noir_IEEE754)

| Operation | Float64 ACIR | Cairo Estimate |
|-----------|--------------|----------------|
| add | 714 | 2,100-3,600 |
| sub | 715 | 2,100-3,600 |
| mul | 547 | 1,600-2,700 |
| div | 4,106 | 12,000-20,000 |

**Division is 8x more expensive than multiplication.**

---

## 4. Recommended Approach: Fraud Proofs

### Why Fraud Proofs Work

| Approach | Cost per Hash | Practical? |
|----------|---------------|------------|
| Pure ZK | ~$626 | No |
| Fraud Proof | ~$0.08/dispute | Yes |

Most claims are honest → disputes are rare → amortized cost is negligible.

### MoneroVM Fraud Proof Design

1. **Optimistic execution**: Assume validity unless challenged
2. **Bisection protocol**: Binary search to disputed instruction (11 rounds for 2048 instructions)
3. **Single instruction verification**: On-chain verification of one state transition
4. **Gas cost**: 15K-391K per instruction verification

### Dispute Resolution Gas Costs

| Verifier Type | L2 Gas | Notes |
|---------------|--------|-------|
| Simple integer | ~16K-20K | IADD_R, ISUB_R, IMUL_R |
| Complex integer | ~332K-335K | IROR_R, IROL_R |
| Memory + Merkle | ~387K-391K | IADD_M with 15-level proof |
| **Total dispute** | **~787K** | Pre+post state hash + instruction |

---

## 5. Implementation Learnings

### E-group Exponent Constraints

Group E registers mask the exponent to a limited range:
```cpp
exponent = (exponent & 0x7FF) | 0x300;  // Forces exponent to valid range
```

This prevents underflow/overflow to infinity and avoids subnormal numbers.

### Key Implementation Fixes

| Issue | Resolution |
|-------|------------|
| Bit 10 preservation bug | Now always 0, not preserved from input |
| eMask 8-bit vs 64-bit | Full 64-bit mask with 22-bit mantissa + exponent |
| INT32_MIN conversion | 0x80000000 → 0xC1E0000000000000 verified |

---

## 6. Research Value

These findings are publishable:
- "Feasibility Analysis of Trustless RandomX Verification in Zero-Knowledge"
- Quantifies why RandomX is ZK-resistant (by design)
- Documents Cairo steps as dominant bottleneck (not memory/FP)
- Proposes fraud proofs as practical alternative
- Venues: Financial Cryptography, ACM CCS Workshop, IEEE S&P

---

## References

### RandomX Specification
- [RandomX Floating Point Registers](https://github.com/tevador/RandomX/blob/master/doc/specs.md#43-floating-point-registers)
- [RandomX FP Instructions](https://github.com/tevador/RandomX/blob/master/doc/specs.md#53-floating-point-instructions)
- [RandomX VM Implementation](https://github.com/tevador/RandomX/blob/master/src/vm_interpreted.cpp)

### Academic Papers
- [ZKLP Paper (2024)](https://arxiv.org/abs/2404.14983) - IEEE-754 in ZK
- [Succinct ZK for FP (CCS'22)](https://par.nsf.gov/servlets/purl/10408517) - Approximate correctness

### Cairo/STWO
- [STWO Prover](https://l2beat.com/zk-catalog/stwo) - 100x faster than Stone
- [Cairo felt252 in M31](https://docs.starknet.io/learn/S-two-book/cairo-air/basic-building-blocks)
