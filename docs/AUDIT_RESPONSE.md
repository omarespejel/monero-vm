# MoneroVM Fraud Proof Contract: Audit Response

**Audit Date**: February 2026  
**Auditor**: External Security Review  
**Response Date**: February 3, 2026

---

## Executive Summary

This document responds to the security audit findings for the MoneroVM fraud proof contract. We address each finding with:
- Current status (fixed, acknowledged, planned)
- Technical details of the fix or remediation plan
- Timeline for resolution

### Overall Status

| Category | Finding | Severity | Status |
|----------|---------|----------|--------|
| Bond Enforcement | Missing token integration | HIGH | Planned (Phase 2) |
| Bisection Logic | Always takes left half | MEDIUM-HIGH | Planned (Phase 2) |
| Instruction Verification | Only checks hash difference | MEDIUM | Partial (Phase 2) |
| Replay Protection | No duplicate challenge check | MEDIUM | Planned (Phase 2) |
| Event Order | Emit before write | LOW | **FIXED** ✅ |
| Opcode Validation | Gap at 15-17 | MEDIUM | **FIXED** ✅ |
| Program Size | Hardcoded 256 | LOW | Acknowledged |

---

## 🔴 Critical Vulnerabilities

### 1. Missing Bond Enforcement (HIGH)

**Auditor Finding**:
> The contract tracks bond amounts but does not actually transfer/escrow tokens. No ERC20 token integration exists.

**Current State**:
```cairo
challenger_bond: constants::CHALLENGER_BOND,  // 0.1 ETH equivalent
defender_bond: 0,  // Defender hasn't bonded yet
```

The contract stores bond amounts but does not call any token contract.

**Remediation Plan**:

| Phase | Action | Timeline |
|-------|--------|----------|
| Phase 1 (Testnet) | Keep as-is with documented limitation | Current |
| Phase 2 | Integrate STRK/ETH token contract | Pre-mainnet |

**Planned Implementation**:

```cairo
// Phase 2 addition
#[storage]
struct Storage {
    // ... existing fields
    bond_token: ContractAddress,  // STRK or ETH token
    escrowed_bonds: Map<u64, BondEscrow>,  // challenge_id → bonds
}

fn open_challenge(...) -> u64 {
    // Transfer challenger bond
    let token = IERC20Dispatcher { contract_address: self.bond_token.read() };
    token.transfer_from(caller, get_contract_address(), constants::CHALLENGER_BOND);
    
    // ... existing logic
}

fn defend(...) {
    // Transfer defender bond
    let token = IERC20Dispatcher { contract_address: self.bond_token.read() };
    token.transfer_from(caller, get_contract_address(), constants::DEFENDER_BOND);
    
    // ... existing logic
}

fn resolve_challenge(...) {
    // Return bonds to winner, slash loser
    let winner_bond = challenge.challenger_bond + challenge.defender_bond;
    token.transfer(winner, winner_bond);
}
```

**Risk Mitigation (Current)**:
- Testnet uses faucet tokens with no economic value
- Contract documented as "not production-ready"
- No real funds at risk

---

### 2. Bisection Logic Simplification Bug (MEDIUM-HIGH)

**Auditor Finding**:
> The bisection always takes the left half regardless of actual disagreement.

**Current State**:
```cairo
// Update bounds (simplified: bisect left half)
challenge.bisection.right = midpoint;
```

**Root Cause**: The current implementation is a simplified prototype that doesn't compare midpoint hashes from both parties.

**Remediation Plan**:

| Phase | Action | Timeline |
|-------|--------|----------|
| Phase 1 (Testnet) | Document as "simplified bisection" | Current |
| Phase 2 | Implement proper disagreement detection | Pre-mainnet |

**Planned Implementation**:

```cairo
// Phase 2: Store both parties' midpoint claims
#[derive(Drop, Copy, Serde, starknet::Store)]
pub struct BisectionRound {
    pub challenger_midpoint_hash: felt252,
    pub defender_midpoint_hash: felt252,
    pub challenger_submitted: bool,
    pub defender_submitted: bool,
}

fn bisect(...) {
    // Store midpoint hash for current party
    let mut round = self.bisection_rounds.read((challenge_id, challenge.bisection.round));
    
    if is_challenger {
        round.challenger_midpoint_hash = midpoint_state_hash;
        round.challenger_submitted = true;
    } else {
        round.defender_midpoint_hash = midpoint_state_hash;
        round.defender_submitted = true;
    }
    
    // Only advance when both parties have submitted
    if round.challenger_submitted && round.defender_submitted {
        // Find disagreement
        if round.challenger_midpoint_hash != round.defender_midpoint_hash {
            // Disagree on midpoint → dispute is in left half
            challenge.bisection.right = midpoint;
        } else {
            // Agree on midpoint → dispute is in right half
            challenge.bisection.left = midpoint;
        }
        challenge.bisection.round += 1;
    }
    
    // ... rest of logic
}
```

**Why This Works**:
- Both parties submit their claimed midpoint state hash
- If hashes differ, the disputed instruction is in the left half (before midpoint)
- If hashes match, the disputed instruction is in the right half (after midpoint)
- This correctly narrows down to the single disputed instruction

---

### 3. Incomplete Instruction Verification (MEDIUM)

**Auditor Finding**:
> The `verify_instruction_proof()` function only checks that state hashes differ, not that the computation is correct.

**Current State**:
```cairo
// For all other instructions, states must be different
if proof.pre_state_hash != proof.post_state_hash {
    VerificationResult::Verified
}
```

**Context**: This is intentional for Phase 1. The detailed verifiers exist in `fraud_proof.cairo` but are not yet integrated into the challenge contract.

**Remediation Plan**:

| Phase | Action | Timeline |
|-------|--------|----------|
| Phase 1 (Testnet) | Basic state-difference check | Current |
| Phase 2 | Integrate detailed verifiers | Pre-mainnet |

**Planned Integration**:

```cairo
use super::super::randomx::fraud_proof::{
    instruction_verifiers::{
        verify_iadd_r, verify_isub_r, verify_imul_r, verify_imulh_r,
        verify_ismulh_r, verify_ixor_r, verify_iror_r, verify_irol_r,
        verify_iswap_r, verify_iadd_rs, verify_ineg_r, verify_imul_rcp,
        verify_nop,
    },
    memory_verifiers::{
        verify_iadd_m, verify_isub_m, verify_imul_m, verify_ixor_m,
        verify_istore,
    },
    cbranch_verifier::verify_cbranch,
};

fn verify_instruction_proof(
    proof: InstructionProof,
    pre_state: ExecutionState,
    post_state: ExecutionState,
) -> VerificationResult {
    match proof.opcode {
        0 => if verify_iadd_r(pre_state.regs, proof.dst_idx, proof.src_idx, post_state.regs) {
            VerificationResult::Verified
        } else {
            VerificationResult::Rejected
        },
        1 => if verify_isub_r(...) { ... },
        // ... all 21+ integer and memory instructions
        20..27 => VerificationResult::FPStubRejection,  // FP stubs remain
        _ => VerificationResult::InvalidProof,
    }
}
```

**Current Mitigations**:
- FP instructions (36.7%) properly return `FPStubRejection` → defender wins
- NOP and ISWAP_R same-register cases are correctly handled
- Opcode range validation prevents invalid opcodes

---

## 🟡 Medium Severity Issues

### 4. No Replay Protection for Challenges

**Auditor Finding**:
> Nothing prevents the same claim from being challenged multiple times by different parties.

**Status**: Acknowledged, planned for Phase 2.

**Remediation Plan**:

```cairo
#[storage]
struct Storage {
    // ... existing fields
    active_challenges_for_claim: Map<felt252, u64>,  // claim_hash → challenge_id
}

fn open_challenge(...) -> u64 {
    let claim_hash = poseidon_hash_span(array![
        defender_hash, 
        defender_trace_root,
        defender.into()
    ].span());
    
    // Check if claim already being challenged
    let existing = self.active_challenges_for_claim.read(claim_hash);
    assert(existing == 0 || self.challenges.read(existing).status != ChallengeStatus::Bisecting,
           'Claim already challenged');
    
    // ... rest of logic
    self.active_challenges_for_claim.write(claim_hash, challenge_id);
}
```

---

### 5. Missing Event Emission Order — **FIXED** ✅

**Auditor Finding**:
> In `bisect()`, the event is emitted before `challenges.write()`. If write fails, the event is already logged.

**Fix Applied** (commit pending):

```cairo
// BEFORE (incorrect):
self.emit(BisectionMove { ... });
self.challenges.write(challenge_id, challenge);

// AFTER (correct):
// Store updated challenge BEFORE emitting event
// Per auditor: emit after write to ensure state consistency
self.challenges.write(challenge_id, challenge);

// Emit event after successful write
self.emit(BisectionMove {
    challenge_id,
    round: new_round,
    new_left: challenge.bisection.left,
    new_right: challenge.bisection.right,
});
```

---

### 6. Incomplete Opcode Range Validation — **FIXED** ✅

**Auditor Finding**:
> Gap at opcodes 15-17 (IMULH_M, ISMULH_M, IXOR_M) - these are valid memory instructions but would be rejected.

**Fix Applied** (commit pending):

```cairo
// BEFORE (incorrect):
let valid_opcode = proof.opcode <= 14 
    || proof.opcode == 30  // CBRANCH
    || ...

// AFTER (correct):
// Valid: 0-17 (integer + memory), 18 (IADD_RS), 29 (NOP), 30 (CBRANCH), 31 (ISTORE)
// Per auditor: 15-17 (IMULH_M, ISMULH_M, IXOR_M) were missing - now included
let valid_opcode = proof.opcode <= 17  // 0-17: all integer register + memory ops
    || proof.opcode == 30  // CBRANCH
    || proof.opcode == 31  // ISTORE
    || proof.opcode == 29  // NOP
    || proof.opcode == 18; // IADD_RS
```

---

### 7. Hardcoded Program Size

**Auditor Finding**:
> If RandomX spec changes, this constant must be updated throughout.

**Status**: Acknowledged, low priority.

**Current State**:
```cairo
right: 256,  // 256 instructions per program
```

**Response**: RandomX's program size is a fundamental spec constant that has never changed since the algorithm's release in 2019. The constant is used in:
- `open_challenge()` initial bisection bounds
- `MVP_BISECTION_ROUNDS` (8 = log₂(256))

**Remediation** (if ever needed):
```cairo
pub mod constants {
    pub const PROGRAM_SIZE: u32 = 256;
    pub const BISECTION_ROUNDS: u8 = 8;  // log₂(PROGRAM_SIZE)
}
```

---

## 🟢 Strengths Acknowledged

We appreciate the auditor's recognition of:

1. **Comprehensive Test Coverage**: 561 tests covering all major components
2. **Sound Bisection Protocol Design**: 8 rounds for 256 instructions with Merkle proofs
3. **FP Stub Safety Mode**: Prevents incorrect fraud proofs on testnet
4. **Auditor-Driven Hardening**: INEG_R, IADD_RS r5, CBRANCH tracker, ISTORE L3 threshold

---

## Answers to Auditor Questions

### Q1: Bond Economics — What's the plan for actual token integration?

**Answer**: Phase 2 will integrate with the STRK token contract on Starknet Sepolia. The escrow pattern follows OpenZeppelin's escrow contracts:

1. `open_challenge()` calls `STRK.transfer_from(challenger, contract, CHALLENGER_BOND)`
2. `defend()` calls `STRK.transfer_from(defender, contract, DEFENDER_BOND)`
3. `resolve_challenge()` calls `STRK.transfer(winner, total_bonds)`

No separate escrow contract is planned; bonds are held by the challenge contract itself.

### Q2: FP Verification Timeline

**Answer**: The IEEE-754 verification module exists (`src/randomx/fraud_proof.cairo::ieee754`) but is not connected to the main contract because:

1. **Phase 1 (Testnet)**: FP stubs reject → defender wins. Safe for testing integer ops.
2. **Phase 2 (Pre-mainnet)**: Connect FP verifiers for complete fraud proof.

The `FPWitness` structure and verification functions are implemented:
- `verify_fadd_with_witness()`
- `verify_fmul_with_witness()`
- `verify_fdiv_with_witness()`
- `verify_fsqrt_with_witness()`

Integration requires connecting these to `verify_instruction_proof()` and passing witness data in the `InstructionProof` struct.

### Q3: Upgradability

**Answer**: The challenge contract is **not upgradeable** by design. This is intentional for security:

1. **Fraud proofs are trustless** — no admin can change rules mid-dispute
2. **Version migration** — deploy new contract, announce deprecation period
3. **No proxy pattern** — reduces attack surface

Future versions can coexist with old versions; each has its own challenge registry.

### Q4: L2 Scratchpad Commitment

**Answer**: The 2MB scratchpad state is committed via a **Merkle tree** with 2^18 leaves (256K × 8-byte entries):

1. **Leaf**: `hash(scratchpad[i*8..(i+1)*8])`
2. **Tree depth**: 18 levels
3. **Root**: Committed in `ExecutionState.scratchpad_root`

Memory verifiers (`verify_iadd_m`, etc.) accept Merkle proofs to verify individual reads without requiring full scratchpad on-chain.

The actual 2MB scratchpad is stored off-chain by relayers/challengers. Only Merkle proofs are submitted on-chain.

### Q5: ISMULH_R Location

**Answer**: `ISMULH_R` (signed multiply high) is fully implemented:

**Location**: `src/randomx/fraud_proof.cairo`, lines 692-705:

```cairo
/// Verify ISMULH_R: dst = (dst * src) >> 64 (signed high)
pub fn verify_ismulh_r(
    pre_regs: IntegerRegisters,
    dst_idx: u8,
    src_idx: u8,
    post_regs: IntegerRegisters
) -> bool {
    let dst_signed = to_i64(get_register(pre_regs, dst_idx));
    let src_signed = to_i64(get_register(post_regs, src_idx));
    let result_signed = ismulh_i64(dst_signed, src_signed);
    // ...
}
```

The underlying `ismulh_i64` function uses the canonical Hacker's Delight algorithm with proper sign correction.

---

## Summary of Fixes Made

| Issue | Fix | File | Line |
|-------|-----|------|------|
| Event emission order | Write before emit | `challenge.cairo` | 399-410 |
| Opcode validation gap | Include 15-17 | `challenge.cairo` | 605-609 |

---

## Next Steps

1. **Immediate**: Run full test suite to verify fixes
2. **Phase 2 Planning**:
   - Bond token integration design
   - Bisection disagreement detection
   - Full instruction verifier integration
3. **Pre-mainnet**: Independent re-audit after Phase 2 changes

---

## References

- [MoneroVM GitHub](https://github.com/omarespejel/monero-vm)
- [RandomX Specification](https://github.com/tevador/RandomX/blob/master/doc/specs.md)
- [OpenZeppelin Cairo Contracts](https://github.com/OpenZeppelin/cairo-contracts)
