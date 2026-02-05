# MoneroVM Roadmap

## Current Direction: Fraud Proof Implementation

**Primary Goal**: Complete MoneroVM fraud proof system for trustless RandomX verification
on Starknet, inspired by BitVM's approach for Bitcoin.

**Secondary Goal**: Preserve attestation path for production deployment.

**Research Output**: Document ZK infeasibility findings for academic publication.

---

## Track Status

| Track | Priority | Status | Path |
|-------|----------|--------|------|
| **Trustless Research** | 🔴 PRIMARY | Active | Floating-point feasibility → Paper |
| **Attestation MVP** | 🟡 PRESERVED | Paused | Can resume anytime |

---

## Trustless Research Roadmap

### Phase 1: Feasibility Scoping (COMPLETE - VERDICT: NO-GO FOR PURE ZK)

**Status**: 🔴 **ECONOMICALLY IMPRACTICAL** - Reviewer's final assessment.

| Task | Status | Output |
|------|--------|--------|
| Document RandomX FP instruction set | ✅ Done | FLOATING_POINT_RESEARCH.md |
| Survey existing FP ZK circuits | ✅ Done | ZKLP limited, Noir has all modes |
| Analyze constraint costs | ✅ Done | ~6.26B Sierra gas |
| Scope memory authentication | ✅ Done | S-two handles it fine |
| **Reviewer deep research** | ✅ Done | **DEFINITIVE NO-GO** |

**Reviewer's Final Assessment** (2026-01-31):

| Criterion | Status | Notes |
|-----------|--------|-------|
| Technical Feasibility | ⚠️ MARGINAL | Possible but expensive |
| **Prover Time** | 🔴 HIGH RISK | **10-15 min/hash unacceptable** |
| Memory | ✅ OK | S-two handles large workloads |
| **Cost Efficiency** | 🔴 POOR | **~6.26B Sierra gas/hash** |
| Fraud Proof | ✅ VIABLE | **Strongly recommended** |

**Cost Breakdown**:
| Component | Count | Sierra Gas/op | Total Gas |
|-----------|-------|---------------|-----------|
| Cairo Steps | ~50M | 100 | 5B |
| FP Operations | ~1.5M | ~500 | 750M |
| Poseidon (Merkle) | ~500K | 491 | 245M |
| MUL_MOD | ~200K | 604 | 121M |
| Range Checks | ~2M | 70 | 140M |
| **TOTAL** | | | **~6.26B** |

> **Reviewer Quote**: "Pure ZK verification of RandomX is technically possible but
> economically impractical. A fraud proof or hybrid approach is strongly recommended
> for production deployment."

### Phase 2: Fraud Proof Implementation (CONFIRMED PATH FORWARD)

| Task | Status | Output |
|------|--------|--------|
| Scope 256MB cache proof costs | ✅ Done | **~721M constraints** |
| Analyze access pattern constraints | ✅ Done | 131,072 cache reads/hash |
| Scope scratchpad proof costs | ✅ Done | **~246M constraints** |
| Estimate total memory constraints | ✅ Done | **~967M constraints** |

**Memory Analysis (2026-01-31, Reviewer Revised)**:

| Memory Type | Accesses | Tree Depth | Constraints/Proof | Total |
|-------------|----------|------------|-------------------|-------|
| Scratchpad L3 | 4,096 | 21 | ~2,100 | ~8.6M |
| **Scratchpad L1/L2** | **~112,640** | 18 | ~1,800 | **~203M** |
| Cache (light mode) | 131,072 | 22 | ~2,200 | ~288M |
| **Memory Total** | | | | **~500M** |

**Key Insight**: L1/L2 instruction-level accesses dominate (40% of total), not L3 or Cache.
This was previously unaccounted for.

**Note on L3 Count**: Reviewer says 4,096 (2 random × 2048 iterations). Our earlier 65,536
included ×8 programs and writes. Reviewer's count may be "random reads only" per spec design doc.

**Conclusion**: ~500M constraints is borderline. Need Poseidon benchmark to confirm.

### Phase 2: Fraud Proof Implementation (CONFIRMED PATH)

**Goal**: Implement optimistic verification - the reviewer-recommended approach.

**Timeline**: 2-3 weeks

**Why Fraud Proofs** (Reviewer Assessment):
- Pure ZK: 10-15 min prover time, ~6.26B gas → ❌ Impractical
- Fraud proofs: ~1K constraints per dispute → ✅ 1000× cheaper on average

**Reviewer-Recommended Approaches**:

**Option A: Pure Fraud Proof**
- Execute RandomX natively, only prove disputed segments
- Challenge window: 7 days
- Only prove single instruction if challenged
- **Pros**: 1000× cheaper on average
- **Cons**: Liveness assumptions, challenge delays

**Option B: Hybrid ZK + Fraud Proof** (Recommended)
- Prove deterministic components (hashing, mixing) with ZK
- Use fraud proofs for FP operations
- Most disputes never happen → amortized cost drops dramatically

**Option C: STARK-friendly RandomX Variant**
- Replace IEEE-754 FP with field arithmetic approximation
- Replace AES with Poseidon-based PRNG
- **Tradeoff**: Breaks compatibility with Monero (not recommended)

**Implementation Plan (Option B)**:

| Week | Deliverable |
|------|-------------|
| 1 | State commitment scheme + single-instruction disputes |
| 2 | Bisection protocol (hierarchical) |
| 3 | Bond mechanics + timeout handling |
| 4 | Integration with existing attestation system |

**Hybrid Architecture Flow**:
```
Normal flow (99.9%):
  Relayer quorum attests → Accepted immediately

Disputed flow (0.1%):
  Attestation challenged → Fraud proof game
  Winner determined by ZK proof of single instruction
```

**Parameters** (Based on Arbitrum/Optimism):
| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Challenger bond | 0.1 ETH (~$200) | Prevents spam |
| Defender bond | 0.2 ETH (~$400) | Higher for claimer |
| Bisection timeout | 4 hours | Offline response |
| Final proof timeout | 24 hours | ZK generation |
| Total window | 7 days | Industry standard |

### Phase 3: Prototype Single-Hash Proof

**Goal**: Generate a STARK proof for one RandomX hash (even with limitations).

| Task | Status | Output |
|------|--------|--------|
| Integer-only VM subset | ⏳ TODO | Cairo implementation |
| STWO integration | ⏳ TODO | Proof generation |
| End-to-end benchmark | ⏳ TODO | Performance numbers |

### Phase 4: Publication

**Goal**: Publish feasibility findings regardless of outcome.

**Paper Outline**:
1. Introduction: Trustless cross-chain verification for privacy coins
2. Background: RandomX design and ZK-resistance
3. Challenge: Floating-point in ZK circuits
4. Our Approach: [findings from Phase 1-3]
5. Results: Cost models, benchmarks, feasibility assessment
6. Conclusion: Viability of trustless Monero verification

---

## Completed Infrastructure (Shared by Both Tracks)

These components are production-ready and serve both trustless and attestation paths:

| Component | Tests | Status |
|-----------|-------|--------|
| Integer arithmetic (14 instructions) | 78+ | ✅ Bit-perfect |
| ISMULH_R (signed multiply high) | 9 | ✅ Fixed, all edge cases |
| SuperscalarHash program generation | 78 | ✅ Complete |
| Blake2b hash + generator | 21 | ✅ Complete |
| AesHash1R | 18 | ✅ Complete |
| AesGenerator1R | 14 | ✅ Complete |
| Merkle proof verification | 19 | ✅ Complete |
| Dataset item generation | 12 | ✅ Mostly complete |
| Fraud proof + reviewer edge cases | 97+ | ✅ test_randomx_edge_cases.cairo (Sections 1–21) |

**Full suite: 561 tests passing** (see [SECURITY_AUDIT_NOTES.md](./SECURITY_AUDIT_NOTES.md) for audit test breakdown)

---

## Attestation Path (Preserved)

If trustless proves infeasible, or for faster deployment, the attestation path remains available:

### Existing Attestation Scaffolding

```
src/attestation/
├── event.cairo           # MoneroEvent schema
├── quorum_verifier.cairo # Signature quorum logic
├── relayer_registry.cairo # Relayer management
└── replay_protection.cairo # Nonce tracking
```

### To Resume Attestation Path

1. Finish relayer signature verification
2. Implement quorum threshold logic
3. Add slashing mechanism
4. Deploy to testnet with single relayer
5. Expand to multi-relayer quorum

**Estimated effort if resumed**: 2-4 weeks to MVP

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-01-31 | Pivot to trustless research | Higher impact, novel contribution |
| 2026-01-31 | Preserve attestation path | Fallback if trustless infeasible |

---

## Success Criteria

### Trustless Research Success
- [ ] Clear answer on FP feasibility (yes/no/conditional)
- [ ] Published cost models for RandomX ZK verification
- [ ] Academic paper submitted

### Attestation Fallback Success
- [ ] Testnet deployment with relayer quorum
- [ ] Mainnet deployment with slashing

---

## Next Steps (Immediate)

1. **Document RandomX floating-point spec** - Extract exact FP instruction semantics
2. **Literature review** - Survey existing FP ZK circuits (if any)
3. **Prototype FADD** - Single instruction, measure constraint cost
4. **Analyze Group E registers** - Constrained exponent domain

---

## References

- [RandomX Specification](https://github.com/tevador/RandomX/blob/master/doc/specs.md)
- [TRUSTLESS_RANDOMX_ZK_RESEARCH.md](./TRUSTLESS_RANDOMX_ZK_RESEARCH.md)
- [MONERO_VERIFICATION_ON_STARKNET.md](./MONERO_VERIFICATION_ON_STARKNET.md) (attestation path)
- [SECURITY_AUDIT_NOTES.md](./SECURITY_AUDIT_NOTES.md)
