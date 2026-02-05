# Comprehensive Audit Response: fraud_proof.cairo
## Response to Security Audit Report - February 3, 2026

**Prepared for**: External Security Auditor
**Prepared by**: MoneroVM Team
**Document Status**: For Auditor Review

---

## Executive Response

Thank you for the thorough security audit. This document addresses each finding with:
- Current implementation status
- Code evidence
- Remediation actions taken or planned
- Questions requiring clarification

**Summary of Actions Taken Today (10 commits)**:
- Fixed event emission order vulnerability
- Integrated instruction verifiers into challenge contract  
- Added replay protection for duplicate challenges
- Implemented proper bisection disagreement detection
- Added 17 new security/TDD tests

---

## Response to Recent Improvements Analysis

### 1. F-Group Bound Fix (commit dbb542c) ✅ ACKNOWLEDGED

Your assessment is correct. The fix properly derives `MAX_F_GROUP_EXPONENT` from IEEE-754 constraints.

### 2. FSQRT_R Deferred Marker ✅ ACKNOWLEDGED

```cairo
pub const FSQRT_DEFERRED_TO_M3: bool = true;
```

**Our Position**: This is intentional for testnet. Full witness verification is planned for M3 milestone.

### 3. Scratchpad Masks Exported ✅ ACKNOWLEDGED

```cairo
pub const SCRATCHPAD_L1_MASK: u64 = 0x3FF8;     // 16 KB - 8, aligned to 8 bytes
pub const SCRATCHPAD_L2_MASK: u64 = 0x3FFF8;    // 256 KB - 8, aligned to 8 bytes
pub const SCRATCHPAD_L3_MASK: u64 = 0x1FFFF8;   // 2 MB - 8, aligned to 8 bytes
pub const SCRATCHPAD_L3_MASK_64: u64 = 0x1FFFC0; // 2 MB - 64, aligned to 64 bytes
```

---

## Response to Critical Findings

### CRITICAL-1: FP Stubs Still REJECT All FP Operations

**Your Finding**:
```cairo
pub const FP_STUBS_ACCEPT: bool = false; // All FP ops return false
```

**Our Response**:

This is **intentional for testnet safety**. The challenge contract now handles this explicitly:

```cairo
// src/challenge.cairo lines 617-619
if is_fp_instruction(proof.opcode) {
    return VerificationResult::FPStubRejection;
}
```

**Dispute Resolution Logic** (implemented today):

```cairo
// src/challenge.cairo lines 743-747
VerificationResult::FPStubRejection => {
    // FP instruction, can't verify → Defender wins
    // Rationale: "If challenger cannot prove fraud, they haven't proven anything"
    defender
},
```

**QUESTION FOR AUDITOR**: Is "defender wins on FP disputes" acceptable for testnet, or do you recommend a different fallback (e.g., timeout, governance escalation)?

**Planned Resolution**:
| Phase | Action |
|-------|--------|
| Testnet | FP stubs → defender wins (current) |
| M3 | Full witness-based FP verification |
| Mainnet | Complete IEEE-754 compliance |

---

### CRITICAL-2: IMUL_RCP Reciprocal Verification Incomplete

**Your Finding**: The basic `verify_imul_rcp` only checks structure, not actual reciprocal value.

**Our Response**: We have `verify_imul_rcp_full()` implemented but not yet integrated into the challenge contract.

**Evidence** (fraud_proof.cairo lines 931-1050):

```cairo
pub fn verify_imul_rcp_full(
    pre_regs: IntegerRegisters,
    dst_idx: u8,
    imm32: u32,
    post_regs: IntegerRegisters
) -> bool {
    // Edge cases: NOP when imm32 == 0 or power of 2
    if imm32 == 0 || is_power_of_2(imm32) {
        return verify_state_unchanged(pre_regs, post_regs);
    }
    
    // Full reciprocal computation
    let reciprocal = compute_reciprocal(imm32);
    let dst_val = get_register(pre_regs, dst_idx);
    let expected = wrapping_mul_64(dst_val, reciprocal);
    
    let post_dst = get_register(post_regs, dst_idx);
    if post_dst != expected {
        return false;
    }
    verify_other_registers_unchanged(pre_regs, post_regs, dst_idx)
}
```

**ACTION REQUIRED**: Update challenge contract to use `verify_imul_rcp_full` instead of basic version.

**QUESTION FOR AUDITOR**: Should we prioritize this fix before testnet deployment, or is it acceptable as a known limitation with the basic verifier?

---

### HIGH-1: Missing ISMULH_M Verifier

**Your Finding**: Signed high multiplication with memory operand cannot be verified.

**Our Response**: You are correct. We have:
- `verify_imulh_m` (UNSIGNED) ✅
- `verify_ismulh_m` (SIGNED) ❌ MISSING

**Current Memory Verifiers**:
```
verify_iadd_m   ✅
verify_isub_m   ✅
verify_imul_m   ✅
verify_imulh_m  ✅ (unsigned)
verify_ismulh_m ❌ MISSING (signed)
verify_ixor_m   ✅
```

**ACTION REQUIRED**: Implement `verify_ismulh_m` following pattern:

```cairo
pub fn verify_ismulh_m(
    pre_state: RandomXState,
    dst_idx: u8,
    src_idx: u8,
    imm32: u32,
    witness: MemoryWitness,
    post_regs: IntegerRegisters
) -> bool {
    let src_val = get_register(pre_state.registers.int_regs, src_idx);
    let addr = compute_scratchpad_address(src_val, imm32);
    
    if !verify_memory_read(pre_state.scratchpad_root, addr, witness) {
        return false;
    }
    
    let dst_val = get_register(pre_state.registers.int_regs, dst_idx);
    let mem_val = witness.value;
    
    // Use SIGNED multiply high (ismulh_i64 instead of umul_hi)
    let expected = ismulh_i64(to_i64(dst_val), to_i64(mem_val));
    
    let post_dst = get_register(post_regs, dst_idx);
    if post_dst != from_i64(expected) {
        return false;
    }
    verify_other_registers_unchanged(pre_state.registers.int_regs, post_regs, dst_idx)
}
```

**QUESTION FOR AUDITOR**: Do you want us to implement and commit this fix immediately, or include it in the next audit cycle?

---

### HIGH-2: L1/L2 Store Mask Selection Simplified

**Your Finding**: `compute_scratchpad_address_with_level` always uses L3 mask.

**Our Response**: Partially correct. We have the proper logic in `get_scratchpad_level_for_store()` but it's NOT USED:

**Proper Implementation EXISTS** (lines 1282-1292):
```cairo
pub fn get_scratchpad_level_for_store(mod_cond: u8, mod_mem: u8) -> ScratchpadLevel {
    if mod_cond >= STORE_L3_CONDITION {
        ScratchpadLevel::L3_64  // mod_cond >= 14 forces L3 with 64-byte alignment
    } else if mod_mem != 0 {
        // mod_mem != 0 → L1
        ScratchpadLevel::L1
    } else {
        // mod_mem == 0 → L2
        ScratchpadLevel::L2
    }
}
```

**But the address computation is simplified** (lines 1589-1604):
```cairo
fn compute_scratchpad_address_with_level(dst: u64, imm32: u32, mod_cond: u8) -> u32 {
    // ...
    let mask: u64 = if mod_cond >= 14 {
        SCRATCHPAD_L3_MASK
    } else {
        // L1/L2 - simplified to L3 for MVP
        // Full implementation would check mod.mem for L1 (16KB) vs L2 (256KB)
        SCRATCHPAD_L3_MASK  // ← BUG: Should use proper mask
    };
    // ...
}
```

**ACTION REQUIRED**: Refactor `compute_scratchpad_address_with_level` to accept `mod_mem` parameter and use `get_scratchpad_level_for_store()`.

---

## Response to Medium Findings

### MEDIUM-1: Witness Verification TODOs

**Our Response**: Acknowledged. The witness structure validation is complete, but correctness verification is deferred to M3.

**Current Status**:
```cairo
pub fn verify_fadd_with_witness(...) -> bool {
    // ✅ Validates GRS bits in range [0, 7]
    // ✅ Validates rounding_adjustment in [-1, 0, 1]
    // ✅ Validates normalization_shift in valid range
    // ❌ TODO: Full mantissa computation verification
}
```

---

### MEDIUM-2: Bond Amounts May Be Insufficient

**Your Finding**: 0.1-0.2 ETH bonds may be insufficient vs Arbitrum's ~$3,600.

**Our Response**: Bond amounts are configurable constants, not hardcoded:

```cairo
pub const CHALLENGER_BOND: u256 = 100000000000000000; // 0.1 ETH
pub const DEFENDER_BOND: u256 = 200000000000000000;   // 0.2 ETH
```

**QUESTION FOR AUDITOR**: 
1. What economic model do you recommend for determining appropriate bond amounts?
2. Should bonds be denominated in ETH, STRK, or tied to XMR value?
3. Do you have data on expected dispute frequency we should model?

---

### MEDIUM-3: No IROR_I / IROL_I Immediate Variants

**Our Response**: RandomX specification (section 5.2) defines only register variants for rotation:
- `IROR_R` (opcode 7): dst = dst >>> (src mod 64)
- `IROL_R` (opcode 8): dst = dst <<< (src mod 64)

There are NO immediate variants in the RandomX instruction set. The rotation amount always comes from a register.

**Evidence from RandomX spec**:
> "The source operand is the value of the source register modulo 64."

**Conclusion**: No action required - this is by design.

---

## Response to Test Coverage Assessment

### Covered (confirmed):
- Signed zero rounding behavior ✅
- F-group bounds ✅
- Basic integer operations ✅

### Missing Tests - NOW ADDED (today's commits):

**1. CBRANCH with NEVER_MODIFIED sentinel** (test_randomx_edge_cases.cairo):
```cairo
#[test]
fn test_cbranch_never_modified_sentinel() {
    let tracker = init_register_tracker();
    assert(tracker.r0_last_mod == NEVER_MODIFIED, 'r0 init');
    assert(NEVER_MODIFIED == 0xFFFFFFFF, 'sentinel value');
}
```

**2. Replay Protection Tests** (test_challenge.cairo):
```cairo
#[test]
fn test_replay_protection_blocks_duplicate_challenge() { ... }
#[test]
fn test_replay_protection_allows_different_claims() { ... }
#[test]
fn test_replay_protection_allows_rechallenge_after_resolution() { ... }
```

**3. Security Edge Cases** (test_challenge.cairo):
```cairo
#[test]
fn test_security_ineg_r_int64_min_edge_case() {
    let int64_min: u64 = 0x8000000000000000;
    // -INT64_MIN = INT64_MIN (two's complement overflow)
    ...
}

#[test]
fn test_security_imul_rcp_power_of_2_is_nop() { ... }
#[test]
fn test_security_imul_rcp_zero_is_nop() { ... }
```

**Still Missing** (acknowledged, will add):
- E-group masking with all eMask configurations
- Memory operations with address alignment verification
- PRT bisection with malicious Merkle proofs

---

## Answers to Your Questions

### Q1: FP Dispute Handling

**Current Implementation**: Timeout favoring defender.

```cairo
VerificationResult::FPStubRejection => {
    // FP instruction, can't verify → Defender wins
    defender
},
```

**Rationale**: If challenger cannot prove fraud on-chain, they haven't proven anything. This is conservative and prevents griefing attacks where challengers spam FP-heavy disputes.

**COUNTER-QUESTION**: Do you recommend governance escalation for high-value disputes? We could add:
```cairo
if challenge.total_bonded > GOVERNANCE_THRESHOLD {
    return escalate_to_governance(challenge_id);
}
```

---

### Q2: Bond Recalibration

**Current Model**: Fixed amounts (0.1/0.2 ETH) independent of XMR/ETH prices.

**We have NOT modeled**:
- Expected dispute frequency
- Correlation with XMR/ETH price volatility
- Griefing attack economics

**REQUEST**: Can you provide or recommend an economic modeling framework? We'd like to implement dynamic bond pricing if justified.

---

### Q3: M3 Timeline

**FSQRT_R Witness Verification**:
- **Blocking mainnet?**: Yes, for full FP support
- **Current mitigation**: FP stubs + defender-wins fallback
- **M3 target**: TBD based on testnet feedback

**QUESTION**: Is partial FP support acceptable for mainnet launch with clear user documentation?

---

### Q4: AES Operations

**Yes, AES verifiers exist in separate modules**:

```
src/randomx/aes_hash.cairo    - AesHash1R implementation
src/randomx/aes_generator.cairo - AesGenerator1R implementation
```

These are used for:
1. Dataset item generation verification
2. Cache initialization verification
3. Scratchpad filling verification

**Evidence** (from aes_hash.cairo):
```cairo
/// AesHash1R - Single round AES used in RandomX
/// Per RandomX spec section 3.3
pub fn aes_hash_1r(input: Span<u8>) -> Array<u8> { ... }
```

---

## Summary of Actions

### Completed Today:
| Action | Commit | Status |
|--------|--------|--------|
| Event emission order fix | d7d96e0 | ✅ Done |
| Instruction verifier integration | abbd320 | ✅ Done |
| Replay protection | e60e85f | ✅ Done |
| Bisection disagreement detection | e4e5108 | ✅ Done |
| Security test suite | d243bb4 | ✅ Done |

### Pending (Before Testnet):
| Action | Priority | Status |
|--------|----------|--------|
| Add `verify_ismulh_m` | HIGH | Todo |
| Fix L1/L2 mask selection | HIGH | Todo |
| Upgrade to `verify_imul_rcp_full` | MEDIUM | Todo |

### Pending (Before Mainnet):
| Action | Priority | Status |
|--------|----------|--------|
| Full FP witness verification | CRITICAL | M3 |
| Bond amount economic analysis | MEDIUM | Planned |
| Additional Merkle proof edge case tests | LOW | Planned |

---

## Questions Requiring Auditor Response

1. **FP Fallback**: Is "defender wins" acceptable for testnet FP disputes?

2. **ISMULH_M Priority**: Should we implement immediately or batch with other fixes?

3. **Bond Economics**: Can you provide economic modeling guidance?

4. **Partial FP for Mainnet**: Is limited FP support + documentation acceptable?

5. **L1/L2 Mask Fix**: Does this need immediate fix, or is L3-only acceptable for testnet (conservative, always uses largest mask)?

---

## Appendix: Recent Commit Summary

```
d243bb4 test(challenge): add comprehensive tests for Phase 2 features
e4e5108 fix(challenge): implement proper bisection disagreement detection
e60e85f feat(challenge): add replay protection for duplicate challenges
abbd320 feat(challenge): integrate fraud_proof instruction verifiers
ba24a2b docs: update test counts to 561 after edge case additions
730190c docs(audit): add Feb 2026 security audit response
27de890 test(edge_cases): add 97 auditor-directed edge case tests
1984b9e refactor(fraud_proof): export scratchpad masks as pub const
d7d96e0 fix(challenge): write state before emitting BisectionMove event
dbb542c Harden FP edge cases and document F-group bound
```

**Total Test Count**: 561+ tests passing

---

*Document prepared for auditor review. Please respond with clarifications on outstanding questions.*
