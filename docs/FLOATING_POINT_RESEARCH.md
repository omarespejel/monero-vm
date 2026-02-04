# MoneroVM: Floating-Point ZK Feasibility Research

## Goal

Determine if IEEE-754 double precision floating-point operations with 4 runtime-selectable
rounding modes can be proven in ZK at acceptable cost for RandomX verification.

**Conclusion**: Pure ZK is economically impractical. MoneroVM uses fraud proofs instead.

---

## Prior Art Analysis (Auditor Validated)

### ZKLP (2024) - LIMITED APPLICABILITY ⚠️

**Source**: [arxiv.org/abs/2404.14983](https://arxiv.org/abs/2404.14983)

| Claim | Reality |
|-------|---------|
| "64 constraints per FP mult" | **Misleading** - amortized over 2^15 ops |
| IEEE-754 compliant | **Only roundTiesToEven** - missing 3 modes |
| Directly portable | **No** - gnark (BN254) vs Cairo (M31) |

**Verdict**: Useful for algorithmic understanding, not directly usable.

### Noir IEEE-754 (2024) - REFERENCE WITH CAVEATS ⚠️

**Source**: [github.com/jeswr/noir_IEEE754](https://github.com/jeswr/noir_IEEE754)

| Feature | Status | Concern |
|---------|--------|---------|
| All 5 rounding modes | ✅ Implemented | Only 1 tested |
| Actual gate counts | ✅ Published | Division very expensive |
| Float64 support | ✅ Available | - |
| **Security audit** | ❌ None | AI-generated code |
| **Test coverage** | ⚠️ Limited | Only roundTiesToEven tested |

**CRITICAL WARNINGS** (Auditor Assessment):
1. "Has not been security reviewed and should not be used in production"
2. "This library is largely AI-generated"
3. Only tests roundTiesToEven - **other 3 modes untested**
4. RandomX requires ALL 4 rounding modes dynamically

**Actual Gate Counts (Non-Amortized)**:

| Operation | Float64 ACIR | Float64 Brillig | Cairo Estimate |
|-----------|--------------|-----------------|----------------|
| add | 714 | 34 | **2,100-3,600** |
| sub | 715 | 34 | **2,100-3,600** |
| mul | 547 | 34 | **1,600-2,700** |
| **div** | **4,106** | 34 | **12,000-20,000** |

**Division is 8x more expensive than multiplication!**

### Field Size Implications

| System | Field Size | 64-bit Value Representation |
|--------|------------|----------------------------|
| gnark/Noir | ~254 bits | 1 field element |
| Cairo (felt252) | ~252 bits | 1 field element |
| STWO (M31) | 31 bits | **3 limbs** (ceil(64/31)) |

**Key Insight**: M31 decomposition adds 3-5x constraint overhead vs Noir.

### Garaga SDK: Noir-to-Cairo Bridge (2025)

**Source**: [garaga.gitbook.io](https://garaga.gitbook.io/garaga/smart-contract-generators/noir)

| Feature | Status |
|---------|--------|
| Noir → Cairo verifier | ✅ Production (v1.0.1) |
| UltraHonk support | ✅ Available |
| Deploy to Starknet | ✅ Supported |

**How it works**:
1. Write Noir program → `nargo build`
2. Generate verification key → `bb write_vk`
3. Generate Cairo verifier → `garaga gen --system ultra_keccak_zk_honk`
4. Deploy `honk_verifier.cairo` to Starknet

**Potential Approach**: Use Noir IEEE-754 + Garaga SDK to verify FP proofs on Starknet.

**HOWEVER** (Auditor Assessment):
- UltraHonk uses Keccak (136k gas per call on Starknet)
- 900M constraint proof would be **impractical to verify in single tx**
- Would need **proof recursion/aggregation**
- Noir IEEE-754 library needs security audit first

---

## RandomX Floating-Point Specification

### FP Instructions (9 total, ~36.7% of VM instructions)

| Instruction | Operation | Description |
|-------------|-----------|-------------|
| FADD_R | `dst = dst + src` | Add register to register |
| FADD_M | `dst = dst + [mem]` | Add memory to register |
| FSUB_R | `dst = dst - src` | Subtract register from register |
| FSUB_M | `dst = dst - [mem]` | Subtract memory from register |
| FMUL_R | `dst = dst * src` | Multiply register by register |
| FDIV_M | `dst = dst / [mem]` | Divide register by memory |
| FSQRT_R | `dst = sqrt(dst)` | Square root |
| FSWAP_R | `swap(dst, src)` | Swap two registers |
| CFROUND | `fprc = src` | Set rounding mode |

### Rounding Modes (fprc register)

| fprc | IEEE-754 Mode | Behavior |
|------|---------------|----------|
| 0 | roundTiesToEven | Round to nearest, ties to even (default) |
| 1 | roundTowardNegative | Always round toward -∞ |
| 2 | roundTowardPositive | Always round toward +∞ |
| 3 | roundTowardZero | Truncate toward zero |

### Register Groups

RandomX has two FP register groups with different constraints:

| Group | Registers | Exponent Range | Notes |
|-------|-----------|----------------|-------|
| **F** | f0-f3 | Full IEEE-754 | Additive operations |
| **E** | e0-e3 | Constrained (2^-240 to 2^240) | Multiplicative operations |

**Key Insight**: Group E registers have constrained exponents, which may simplify ZK proving.

### IEEE-754 Double Precision Format

```
┌─────┬─────────────┬────────────────────────────────────────────────────┐
│Sign │  Exponent   │                    Mantissa                        │
│ 1b  │    11b      │                      52b                           │
└─────┴─────────────┴────────────────────────────────────────────────────┘
```

- Sign: 1 bit
- Exponent: 11 bits (biased by 1023)
- Mantissa: 52 bits (implicit leading 1)
- Total: 64 bits

---

## Research Questions

### Q1: Can we exploit Group E's constrained exponent range?

Group E registers mask the exponent to a limited range:
```cpp
// From RandomX spec
exponent = (exponent & 0x7FF) | 0x300;  // Forces exponent to valid range
```

This means:
- Exponents are bounded to ~±240
- Underflow/overflow to infinity is prevented
- Subnormal numbers are avoided

**Hypothesis**: Constrained exponents may allow simpler FP circuits.

### Q2: What's the constraint cost per FP operation?

Need to benchmark:
- Addition/Subtraction (alignment + add + normalize)
- Multiplication (mantissa multiply + exponent add + normalize)
- Division (iterative or lookup-based)
- Square root (iterative or lookup-based)

### Q3: Is fixed-point approximation viable?

RandomX's FP operations affect the final hash. Options:
- **Exact IEEE-754**: Guaranteed correct, expensive
- **Fixed-point approximation**: May produce wrong hash
- **Hybrid**: Exact for edge cases, approximate otherwise

**Note**: Quarkslab audit found "no significant optimization even with approximations" -
this suggests RandomX is resistant to FP shortcuts.

### Q4: Can lookup tables cover edge cases?

For operations like FSQRT, a lookup table approach might work:
- Input: 64-bit double
- Output: 64-bit double
- Table size: 2^64 entries = infeasible directly

But with mantissa truncation:
- 52-bit mantissa → 16-bit lookup + interpolation?
- Need to verify error bounds

---

## Literature Review

### Existing FP ZK Work

| Project | Approach | Limitations |
|---------|----------|-------------|
| [TODO] | [TODO] | [TODO] |

**Note**: No known production ZK circuits for IEEE-754 with multiple rounding modes.

### Related Work

- **ZK-friendly hashes**: SHA-256, Poseidon, Blake (all integer-based)
- **ZK-unfriendly**: Floating-point, AES (without algebraic optimizations)

---

## Prototype Plan (Updated with Noir Reference)

### Reference Implementation

Use **Noir IEEE-754** as primary reference:
- `types.nr` - Float64 struct definition
- `utils.nr` - Rounding mode logic
- `gate_counts.json` - Benchmark comparison

### Step 1: Cairo Float64 Type

```cairo
/// IEEE-754 double precision floating point
/// Based on Noir's Float64 struct
struct Float64 {
    sign: u8,        // 1 bit
    exponent: u16,   // 11 bits (biased)
    mantissa: u64,   // 52 bits + implicit 1
    is_abnormal: bool, // NaN or Inf flag
}

/// Rounding modes (matches RandomX fprc)
const ROUND_TIES_TO_EVEN: u8 = 0;
const ROUND_TOWARD_NEGATIVE: u8 = 1;
const ROUND_TOWARD_POSITIVE: u8 = 2;
const ROUND_TOWARD_ZERO: u8 = 3;
```

### Step 2: Implement Core Operations

```
Week 1-2: Foundation
├── unpack_double(u64) -> Float64
├── pack_double(Float64) -> u64
├── normalize(Float64) -> Float64
└── Benchmark: target < 100 constraints each

Week 3-4: FADD with roundTiesToEven
├── Port Noir add() logic to Cairo
├── Handle special cases (NaN, Inf, zero)
├── Test against Berkeley TestFloat vectors
└── Benchmark: target < 500 constraints

Week 5-6: All Rounding Modes
├── Implement round_toward_negative()
├── Implement round_toward_positive()
├── Implement round_toward_zero()
└── Test mode switching overhead
```

### Step 3: Go/No-Go Decision

After FADD prototype:
- If < 500 constraints: Proceed to FMUL, FDIV, FSQRT
- If 500-1000 constraints: Evaluate optimizations
- If > 1000 constraints: Pivot to alternatives

### Parallel Track: Alternatives

Document these in case FP is too expensive:
1. **Fraud proofs** - Optimistic execution with challenge period
2. **Fixed-point approximation** - May produce wrong hashes
3. **Hybrid attestation** - FP operations attested, integers verified

---

## Feasibility Assessment (2026-01-31) - FINAL

### Auditor's Definitive Cost Analysis (Sierra Gas)

```
AUDITOR'S FINAL ASSESSMENT (2026-01-31):

| Component           | Count   | Gas/Op | Total Gas  |
|---------------------|---------|--------|------------|
| Cairo Steps (VM)    | ~50M    | 100    | 5.0B       |
| FP Operations       | ~1.5M   | ~500   | 750M       |
| Poseidon (Merkle)   | ~500K   | 491    | 245M       |
| MUL_MOD (64-bit)    | ~200K   | 604    | 121M       |
| Range Checks        | ~2M     | 70     | 140M       |
|---------------------|---------|--------|------------|
| TOTAL               |         |        | ~6.26B     |

PROVER TIME:
- S-two: ~60s for 4M Fibonacci operations
- RandomX: ~10× more complex (memory + FP)
- Estimated: 10-15 MINUTES per hash

VERDICT: 🔴 ECONOMICALLY IMPRACTICAL
- Technically possible
- Not viable for production use
- Fraud proofs STRONGLY recommended
```

**Key Insight**: The bottleneck is **Cairo steps** (~50M ops = 5B gas), not memory or FP.
S-two handles memory fine, but the sheer number of VM operations makes pure ZK impractical.

### Final Go/No-Go Assessment (Auditor's Verdict)

| Criterion | Status | Notes |
|-----------|--------|-------|
| Technical Feasibility | ⚠️ MARGINAL | Possible but expensive |
| **Prover Time** | 🔴 HIGH RISK | **10-15 min/hash unacceptable** |
| Memory | ✅ OK | S-two handles large workloads |
| **Cost Efficiency** | 🔴 POOR | **~6.26B Sierra gas/hash** |
| Fraud Proof Alternative | ✅ VIABLE | **Strongly recommended** |

**Auditor's Conclusion**:
> "Pure ZK verification of RandomX is technically possible but economically impractical.
> A fraud proof or hybrid approach is strongly recommended for production deployment."

**Key Insight**: The bottleneck is **Cairo steps** (~50M operations), not memory or FP.
This was not captured in earlier constraint-based estimates.

### Recommended Path Forward (Auditor's Recommendations)

**Option A: Pure Fraud Proof**
- Execute RandomX natively, only prove disputed segments
- Challenge window: 7 days typical
- **Pros**: 1000× cheaper on average
- **Cons**: Liveness assumptions, challenge delays

**Option B: Hybrid ZK + Fraud Proof** ← **RECOMMENDED**
- Prove deterministic components (hashing, mixing) with ZK
- Use fraud proofs for FP operations
- Most disputes never happen → amortized cost drops dramatically

**Option C: STARK-friendly RandomX Variant**
- Replace IEEE-754 FP with field arithmetic approximation
- Replace AES with Poseidon-based PRNG
- **Tradeoff**: Breaks compatibility with Monero (not recommended)

### Research Value

Findings are highly publishable:
- "Feasibility Analysis of Trustless RandomX Verification in Zero-Knowledge"
- Quantifies why RandomX is ZK-resistant (by design)
- Documents Cairo steps as dominant bottleneck (not memory/FP)
- Proposes fraud proof as practical alternative
- Venues: Financial Cryptography 2027, ACM CCS Workshop, IEEE S&P

---

## Cost Model (Auditor Validated)

### Per-Operation Estimates

| Operation | Noir ACIR | Cairo/M31 Estimate | RandomX Frequency |
|-----------|-----------|-------------------|-------------------|
| FADD | 158 | **475-790** | 21/256 (8.2%) |
| FSUB | 154 | **462-770** | 21/256 (8.2%) |
| FMUL | 126 | **378-630** | 32/256 (12.5%) |
| FDIV | 123 | **369-615** | 4/256 (1.6%) |
| FSQRT | ~200 | **600-1000** | 6/256 (2.3%) |
| FSWAP | ~10 | **30-50** | 4/256 (1.6%) |
| FSCAL | ~50 | **150-250** | 6/256 (2.3%) |

### Full RandomX Hash Estimate

```
Per program iteration:
- 256 instructions
- ~94 FP instructions (36.7%)
- ~162 integer instructions (63.3%)

Per hash:
- 2048 iterations × 8 programs = 16,384 program executions
- FP instructions: 16,384 × 94 = ~1.54M FP ops
- At 500 constraints/op: ~770M constraints for FP alone

This is VERY LARGE but may be feasible with:
- STWO's high throughput
- Parallel proving
- Constraint batching
```

### Go/No-Go Thresholds (Auditor Recommended)

| Metric | GO | NO-GO |
|--------|-----|-------|
| FADD constraints | < 500 | > 1000 |
| Full FP overhead | < 50% of total | > 80% |
| Single hash prove time | < 30 seconds | > 5 minutes |

---

## Decision Points

### Go/No-Go Criteria

| Metric | Threshold | Notes |
|--------|-----------|-------|
| FP ops per hash | Measure | Currently unknown |
| Gas per FP op | < 10,000 L2 gas | Arbitrary threshold |
| Total hash cost | < 100M L2 gas | Must fit in block |
| Proof time | < 1 hour | Practical for proving |

### Outcomes

1. **Feasible**: FP in ZK is practical → Continue to full implementation
2. **Marginally feasible**: High cost but possible → Consider hybrid approach
3. **Infeasible**: Too expensive → Publish findings, consider attestation fallback

---

## Next Actions

- [ ] Extract exact FP semantics from RandomX source
- [ ] Implement `unpack_double` and `pack_double` in Cairo
- [ ] Prototype FADD with mode 0 (roundTiesToEven)
- [ ] Benchmark constraint cost
- [ ] Survey literature for existing FP ZK work

---

## References

### Primary References (Use These)

- [Noir IEEE-754 Library](https://github.com/jeswr/noir_IEEE754) - **Best reference for all rounding modes**
- [Noir gate_counts.json](https://github.com/jeswr/noir_IEEE754/blob/main/gate_counts.json) - Actual constraint counts
- [Berkeley TestFloat](https://github.com/ucb-bar/berkeley-testfloat-3) - IEEE-754 compliance verification

### RandomX Specification

- [RandomX Floating Point Registers](https://github.com/tevador/RandomX/blob/master/doc/specs.md#43-floating-point-registers)
- [RandomX FP Instructions](https://github.com/tevador/RandomX/blob/master/doc/specs.md#53-floating-point-instructions)
- [RandomX VM Implementation](https://github.com/tevador/RandomX/blob/master/src/vm_interpreted.cpp)

### Academic Papers

- [ZKLP Paper (2024)](https://arxiv.org/abs/2404.14983) - IEEE-754 in ZK (limited rounding modes)
- [Succinct ZK for FP (CCS'22)](https://par.nsf.gov/servlets/purl/10408517) - Approximate correctness approach

### Standards

- [IEEE-754 Standard](https://en.wikipedia.org/wiki/IEEE_754)
- [IBM FPgen Test Suite](https://www.research.ibm.com/haifa/projects/verification/fpgen/) - Comprehensive FP tests

### Cairo/STWO

- [STWO Prover](https://l2beat.com/zk-catalog/stwo) - 100x faster than Stone
- [Cairo felt252 in M31](https://docs.starknet.io/learn/S-two-book/cairo-air/basic-building-blocks) - Field decomposition

---

## Implementation Learnings (Jan 2026)

For detailed implementation findings including:
- E-group exponent constraint fixes
- Full 64-bit eMask implementation
- F-group conversion (INT32_MIN edge case)
- Spec vs reference implementation discrepancies

See: **[SECURITY_AUDIT_NOTES.md - Floating-Point Implementation Section](./SECURITY_AUDIT_NOTES.md#floating-point-implementation---critical-findings-jan-2026)**

### Key Implementation Fixes

| Issue | Resolution |
|-------|------------|
| Bit 10 preservation bug | Now always 0, not preserved from input |
| eMask 8-bit vs 64-bit | Full 64-bit mask with 22-bit mantissa + exponent |
| Spec says bits 0-2 = 011 | Reference uses bits 8-9 = 0x3, bits 4-7 dynamic |
| INT32_MIN conversion | 0x80000000 → 0xC1E0000000000000 verified |

### Test Status

**441 tests passing** including:
- `test_e_group_bit_10_is_zero`
- `test_compute_e_mask`
- `test_int32_min_conversion`
- `test_apply_e_group_constraint_with_full_mask`
