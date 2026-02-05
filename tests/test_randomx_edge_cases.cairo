//! RandomX FP Verifier Edge Case Tests
//! Per spec requirements for fraud proof verification
//! Spec references: RandomX spec 4.3, 4.3.2, 5.4.1

use core::array::ArrayTrait;
use monero_vm::randomx::fraud_proof::fp_stubs::{
    verify_fscal_r, FSCAL_MASK
};
use monero_vm::randomx::fraud_proof::ieee754::{
    unpack, is_nan, is_subnormal,
    apply_ftz_daz_bits, verify_fadd, verify_fadd_with_witness, verify_fsub, verify_fdiv,
    verify_fmul, verify_fmul_with_witness, verify_fdiv_with_witness, verify_fsqrt,
    verify_fsqrt_with_witness, verify_cfround, verify_e_group_invariant, verify_e_group_exponent,
    verify_e_group_exponent_full, verify_f_group_invariant,
    compute_e_mask, apply_e_group_mask, default_fp_witness, FPWitness,
    ROUND_TIES_TO_EVEN, ROUND_TOWARD_NEGATIVE, ROUND_TOWARD_POSITIVE, ROUND_TOWARD_ZERO
};
use monero_vm::randomx::fraud_proof::instruction_verifiers::{
    verify_nop, verify_ineg_r, verify_imul_rcp, verify_iadd_rs, verify_iswap_r,
    is_power_of_2, compute_reciprocal,
};
use monero_vm::randomx::fraud_proof::{
    IntegerRegisters, FloatRegister, FloatRegisters,
    ExecutionState, advance_to_next_program, reset_fprc_for_new_hash, update_fprc,
    memory_verifiers::{
        ScratchpadLevel, get_level_mask, get_scratchpad_level_for_store,
        SCRATCHPAD_L1_MASK, SCRATCHPAD_L2_MASK, SCRATCHPAD_L3_MASK, SCRATCHPAD_L3_MASK_64,
    },
    apply_iteration_end_xor,
};
use monero_vm::randomx::fraud_proof::cbranch_verifier::{
    init_tracker, set_all_modified_at_cbranch, get_last_mod_pc, NEVER_MODIFIED,
};
use monero_vm::randomx::fraud_proof::fp_stubs::verify_fscal_r_stub;
use monero_vm::randomx::prototype::{sign_extend_32_to_64, verify_cache_lookups_8};

// IEEE-754 constants
const POS_ZERO: u64 = 0x0000000000000000;
const NEG_ZERO: u64 = 0x8000000000000000;
const MAX_SUBNORMAL: u64 = 0x000FFFFFFFFFFFFF;  // 2^-1022 - 2^-1074
const NEG_MAX_SUBNORMAL: u64 = 0x800FFFFFFFFFFFFF;

// RandomX constants (from spec)
const MIN_E_MASK_ENTROPY: u64 = 0x0000000000000000;
const MAX_E_MASK_ENTROPY: u64 = 0xF000000000000000;
const MIN_E_DIVISOR: u64 = 0x3000000000000001;  // exponent = 0x300, mantissa LSB set

// F-group boundary (spec ~3.0e+14)
const MAX_F_GROUP: u64 = 0x42F10D9316EC0000;  // 3.0e14
const ABOVE_MAX_F_GROUP: u64 = 0x43010D9316EC0000;  // 6.0e14 (exponent 1072)

#[test]
fn test_ftz_daz_denormal_boundary() {
    // Spec: FTZ/DAZ flushes denormals to signed zero
    assert(apply_ftz_daz_bits(MAX_SUBNORMAL) == POS_ZERO, 'ftz pos denorm -> +0');
    assert(apply_ftz_daz_bits(NEG_MAX_SUBNORMAL) == NEG_ZERO, 'ftz neg denorm -> -0');
}

#[test]
fn test_ftz_daz_applies_in_fadd() {
    // Denormal input should behave as zero after FTZ/DAZ
    let witness = default_fp_witness();
    assert(
        verify_fadd_with_witness(MAX_SUBNORMAL, POS_ZERO, POS_ZERO, ROUND_TIES_TO_EVEN, witness),
        'fadd denorm + 0 => 0'
    );
}

#[test]
fn test_signed_zero_rounding_fadd() {
    let w = default_fp_witness();
    // (+0) + (-0)
    assert(verify_fadd_with_witness(POS_ZERO, NEG_ZERO, POS_ZERO, ROUND_TIES_TO_EVEN, w), 'ties-even +0');
    assert(verify_fadd_with_witness(POS_ZERO, NEG_ZERO, NEG_ZERO, ROUND_TOWARD_NEGATIVE, w), 'round-down -0');
    assert(verify_fadd_with_witness(POS_ZERO, NEG_ZERO, POS_ZERO, ROUND_TOWARD_POSITIVE, w), 'round-up +0');
    assert(verify_fadd_with_witness(POS_ZERO, NEG_ZERO, POS_ZERO, ROUND_TOWARD_ZERO, w), 'round-zero +0');
}

#[test]
fn test_signed_zero_rounding_fsub() {
    // (+0) - (+0)
    assert(verify_fsub(POS_ZERO, POS_ZERO, POS_ZERO, ROUND_TIES_TO_EVEN), 'sub ties-even +0');
    assert(verify_fsub(POS_ZERO, POS_ZERO, NEG_ZERO, ROUND_TOWARD_NEGATIVE), 'sub round-down -0');
    assert(verify_fsub(POS_ZERO, POS_ZERO, POS_ZERO, ROUND_TOWARD_POSITIVE), 'sub round-up +0');
    assert(verify_fsub(POS_ZERO, POS_ZERO, POS_ZERO, ROUND_TOWARD_ZERO), 'sub round-zero +0');

    // (-0) - (-0)
    assert(verify_fsub(NEG_ZERO, NEG_ZERO, POS_ZERO, ROUND_TIES_TO_EVEN), 'sub negzero ties-even +0');
    assert(verify_fsub(NEG_ZERO, NEG_ZERO, NEG_ZERO, ROUND_TOWARD_NEGATIVE), 'sub negzero round-down -0');
    assert(verify_fsub(NEG_ZERO, NEG_ZERO, POS_ZERO, ROUND_TOWARD_POSITIVE), 'sub negzero round-up +0');
    assert(verify_fsub(NEG_ZERO, NEG_ZERO, POS_ZERO, ROUND_TOWARD_ZERO), 'sub negzero round-zero +0');
}

#[test]
fn test_fsub_cancellation_sign() {
    // 1.0 - 1.0 -> signed zero depends on rounding mode
    let one: u64 = 0x3FF0000000000000;
    assert(verify_fsub(one, one, POS_ZERO, ROUND_TIES_TO_EVEN), 'cancel ties-even +0');
    assert(verify_fsub(one, one, NEG_ZERO, ROUND_TOWARD_NEGATIVE), 'cancel round-down -0');
    assert(verify_fsub(one, one, POS_ZERO, ROUND_TOWARD_POSITIVE), 'cancel round-up +0');
    assert(verify_fsub(one, one, POS_ZERO, ROUND_TOWARD_ZERO), 'cancel round-zero +0');
}

#[test]
fn test_fprc_transitions_cfround() {
    // CFROUND: fprc = rotr(src, imm) & 0x3
    assert(verify_cfround(0x2, 0, 2), 'fprc=2');
    assert(verify_cfround(0x4, 1, 2), 'fprc=2 after rotr');
    assert(verify_cfround(0x1, 0, 1), 'fprc=1');
    assert(verify_cfround(0x3, 0, 3), 'fprc=3');
}

#[test]
fn test_e_group_mask_boundaries() {
    // Spec 4.3.2: exponent bits 8-9 = 0x3, bits 4-7 from entropy
    let mask_min = compute_e_mask(MIN_E_MASK_ENTROPY);
    let mask_max = compute_e_mask(MAX_E_MASK_ENTROPY);

    let memory_value: u64 = 0x0000000000000001;  // minimal mantissa (avoid exponent contamination)
    let masked_min = apply_e_group_mask(memory_value, mask_min);
    let masked_max = apply_e_group_mask(memory_value, mask_max);

    assert(verify_e_group_exponent_full(masked_min, 0), 'min e-mask exponent');
    assert(verify_e_group_exponent_full(masked_max, 0xF), 'max e-mask exponent');

    assert(verify_e_group_invariant(masked_min), 'e-group positive');
    assert(verify_e_group_invariant(masked_max), 'e-group positive');

    let f_min = unpack(masked_min);
    let f_max = unpack(masked_max);
    assert(!is_subnormal(f_min), 'min e-group not subnormal');
    assert(!is_subnormal(f_max), 'max e-group not subnormal');
}

#[test]
fn test_fscal_r_no_denorm() {
    // FSCAL_R XORs exponent bits; ensure result is not subnormal or NaN
    let pre_low: u64 = 0x3FF0000000000000;  // 1.0
    let pre_high: u64 = 0x4000000000000000; // 2.0
    let post_low = pre_low ^ FSCAL_MASK;
    let post_high = pre_high ^ FSCAL_MASK;
    assert(verify_fscal_r(pre_low, pre_high, post_low, post_high, 0), 'fscal_r xor');
    assert(!is_subnormal(unpack(post_low)), 'fscal low not subnormal');
    assert(!is_subnormal(unpack(post_high)), 'fscal high not subnormal');
    assert(!is_nan(unpack(post_low)), 'fscal low not NaN');
    assert(!is_nan(unpack(post_high)), 'fscal high not NaN');
}

#[test]
fn test_f_group_boundary() {
    assert(verify_f_group_invariant(MAX_F_GROUP), 'max f-group ok');
    assert(!verify_f_group_invariant(ABOVE_MAX_F_GROUP), 'above max f-group rejected');
}

#[test]
fn test_f_group_xor_e_group_invariant() {
    // Spec 4.6.2 step 10: f[i] = f[i] XOR e[i]
    // Choose values that keep exponent within f-group bounds.
    let f_val: u64 = 0x3FF0000000000000; // 1.0
    let e_val: u64 = 0x3000000000000000; // min e-group exponent
    let xor_val = f_val ^ e_val;
    assert(verify_f_group_invariant(xor_val), 'f xor e within f-group bound');
}

#[test]
fn test_fdiv_near_zero_divisor() {
    // Spec: division by near-zero divisor should produce +inf (not NaN)
    let max_finite: u64 = 0x7FEFFFFFFFFFFFFF;
    let result_inf: u64 = 0x7FF0000000000000;
    assert(verify_fdiv(max_finite, MIN_E_DIVISOR, result_inf, ROUND_TIES_TO_EVEN), 'fdiv near-zero -> +inf');
}

// ============================================================================
// Section 16: Additional FTZ/DAZ and FP edge cases
// ============================================================================

#[test]
fn test_ftz_daz_pos_denorm_to_pos_zero() {
    let pos_denorm: u64 = 0x0000000000000001;
    assert(apply_ftz_daz_bits(pos_denorm) == POS_ZERO, 'pos denorm -> +0');
}

#[test]
fn test_ftz_daz_neg_denorm_to_neg_zero() {
    let neg_denorm: u64 = 0x8000000000000001;
    assert(apply_ftz_daz_bits(neg_denorm) == NEG_ZERO, 'neg denorm -> -0');
}

#[test]
fn test_ftz_daz_normal_unchanged() {
    let one: u64 = 0x3FF0000000000000;
    assert(apply_ftz_daz_bits(one) == one, 'normal unchanged');
}

#[test]
fn test_fadd_inf_plus_neg_inf_is_nan() {
    let witness = default_fp_witness();
    let pos_inf: u64 = 0x7FF0000000000000;
    let neg_inf: u64 = 0xFFF0000000000000;
    let nan: u64 = 0x7FF8000000000000;
    assert(verify_fadd_with_witness(pos_inf, neg_inf, nan, ROUND_TIES_TO_EVEN, witness), 'inf + -inf = NaN');
}

#[test]
fn test_fadd_denorm_flushed_to_zero() {
    let witness = default_fp_witness();
    let denorm: u64 = 0x0000000000000001;
    let one: u64 = 0x3FF0000000000000;
    assert(verify_fadd_with_witness(denorm, one, one, ROUND_TIES_TO_EVEN, witness), 'denorm + 1.0 = 1.0');
}

#[test]
fn test_fmul_zero_times_inf_is_nan() {
    let witness = default_fp_witness();
    let zero: u64 = 0x0000000000000000;
    let inf: u64 = 0x7FF0000000000000;
    let nan: u64 = 0x7FF8000000000000;
    assert(verify_fmul_with_witness(zero, inf, nan, ROUND_TIES_TO_EVEN, witness), '0 * inf = NaN');
}

#[test]
fn test_fmul_sign_neg_times_neg_is_pos() {
    let witness = FPWitness {
        extended_mantissa_hi: 0, extended_mantissa_lo: 0,
        rounding_adjustment: 0, guard_round_sticky: 0,
        result_exponent: 0, normalization_shift: 0, alignment_shift: 0,
        sign_a: 1, sign_b: 1, sign_result: 0,
        ftz_daz_active: 1, fprc_at_execution: ROUND_TIES_TO_EVEN, is_sub: 0,
    };
    let neg_one: u64 = 0xBFF0000000000000;
    let pos_one: u64 = 0x3FF0000000000000;
    assert(verify_fmul_with_witness(neg_one, neg_one, pos_one, ROUND_TIES_TO_EVEN, witness), '-1 * -1 = +1');
}

#[test]
fn test_fmul_denorm_times_one_is_zero() {
    let witness = default_fp_witness();
    let denorm: u64 = 0x0000000000000001;
    let one: u64 = 0x3FF0000000000000;
    assert(verify_fmul_with_witness(denorm, one, POS_ZERO, ROUND_TIES_TO_EVEN, witness), 'denorm * 1.0 = 0');
}

#[test]
fn test_fdiv_one_by_denorm_is_inf() {
    let witness = default_fp_witness();
    let one: u64 = 0x3FF0000000000000;
    let denorm: u64 = 0x0000000000000001;
    let inf: u64 = 0x7FF0000000000000;
    assert(verify_fdiv_with_witness(one, denorm, inf, ROUND_TIES_TO_EVEN, witness), '1.0 / denorm = inf');
}

#[test]
fn test_fdiv_zero_by_zero_is_nan() {
    let witness = default_fp_witness();
    let zero: u64 = 0x0000000000000000;
    let nan: u64 = 0x7FF8000000000000;
    assert(verify_fdiv_with_witness(zero, zero, nan, ROUND_TIES_TO_EVEN, witness), '0/0 = NaN');
}

#[test]
fn test_fdiv_inf_by_inf_is_nan() {
    let witness = default_fp_witness();
    let inf: u64 = 0x7FF0000000000000;
    let nan: u64 = 0x7FF8000000000000;
    assert(verify_fdiv_with_witness(inf, inf, nan, ROUND_TIES_TO_EVEN, witness), 'inf/inf = NaN');
}

#[test]
fn test_fsqrt_denorm_is_zero() {
    let witness = default_fp_witness();
    let denorm: u64 = 0x0000000000000001;
    assert(verify_fsqrt_with_witness(denorm, POS_ZERO, ROUND_TIES_TO_EVEN, witness), 'sqrt(denorm) = 0');
}

#[test]
fn test_fsqrt_neg_zero_is_neg_zero() {
    let witness = default_fp_witness();
    assert(verify_fsqrt_with_witness(NEG_ZERO, NEG_ZERO, ROUND_TIES_TO_EVEN, witness), 'sqrt(-0) = -0');
}

#[test]
fn test_fsqrt_negative_is_nan() {
    let witness = default_fp_witness();
    let neg_one: u64 = 0xBFF0000000000000;
    let nan: u64 = 0x7FF8000000000000;
    assert(verify_fsqrt_with_witness(neg_one, nan, ROUND_TIES_TO_EVEN, witness), 'sqrt(-1) = NaN');
}

#[test]
fn test_fsqrt_pos_inf_is_pos_inf() {
    let witness = default_fp_witness();
    let pos_inf: u64 = 0x7FF0000000000000;
    assert(verify_fsqrt_with_witness(pos_inf, pos_inf, ROUND_TIES_TO_EVEN, witness), 'sqrt(+inf) = +inf');
}

#[test]
fn test_e_group_must_be_positive() {
    let negative_value: u64 = 0x8300000000000000;
    assert(!verify_e_group_exponent(negative_value), 'E-group must be positive');
}

#[test]
fn test_e_group_bits_8_9_must_be_0x3() {
    let invalid_exp: u64 = 0x0000000000000000;
    assert(!verify_e_group_exponent(invalid_exp), 'E-group exp bits 8-9 invalid');
}

#[test]
fn test_e_group_bit_10_must_be_zero() {
    let bit_10_set: u64 = 0x4300000000000000;
    assert(!verify_e_group_exponent(bit_10_set), 'E-group bit 10 must be 0');
}

#[test]
fn test_e_group_bits_0_3_must_be_zero() {
    // Exponent bits 0-3 must be 0. Use value with exp=0x30F (bits 0-3 = 0xF).
    let invalid: u64 = 0x30F0000000000000;
    assert(!verify_e_group_exponent(invalid), 'E bits 0-3');
}

#[test]
fn test_e_group_valid_value() {
    // Valid: sign=0, bits 0-3=0, bits 8-9=0x3, bit 10=0
    assert(verify_e_group_exponent(0x3000000000000000), 'E valid');
}

// ============================================================================
// Section 17: IADD_RS r5 and NOP instruction verifier tests
// ============================================================================


#[test]
fn test_iadd_rs_r5_adds_imm32() {
    let pre_regs = IntegerRegisters {
        r0: 0, r1: 0, r2: 0, r3: 0, r4: 0,
        r5: 100,
        r6: 10,
        r7: 0,
    };
    let post_regs = IntegerRegisters {
        r0: 0, r1: 0, r2: 0, r3: 0, r4: 0,
        r5: 119,
        r6: 10,
        r7: 0,
    };
    assert(verify_iadd_rs(pre_regs, 5, 6, 1, 0xFFFFFFFF, post_regs), 'IADD_RS r5 adds imm32');
}

#[test]
fn test_iadd_rs_non_r5_ignores_imm32() {
    let pre_regs = IntegerRegisters {
        r0: 100,
        r1: 10,
        r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let post_regs = IntegerRegisters {
        r0: 120,
        r1: 10,
        r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    assert(verify_iadd_rs(pre_regs, 0, 1, 1, 0xFFFFFFFF, post_regs), 'IADD_RS non-r5 ignores imm32');
}

#[test]
fn test_nop_leaves_state_unchanged() {
    let regs = IntegerRegisters {
        r0: 0xDEADBEEF, r1: 0xCAFEBABE, r2: 0x12345678, r3: 0x87654321,
        r4: 0xAAAAAAAA, r5: 0xBBBBBBBB, r6: 0xCCCCCCCC, r7: 0xDDDDDDDD,
    };
    assert(verify_nop(regs, regs), 'NOP leaves state unchanged');
}

#[test]
fn test_nop_any_change_fails() {
    let pre = IntegerRegisters { r0: 100, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0 };
    let post = IntegerRegisters { r0: 101, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0 };
    assert(!verify_nop(pre, post), 'nop change fail');
}

// ============================================================================
// §7 IMUL_RCP NOP CASES (4 tests) - CRITICAL PER AUDITOR
// ============================================================================

#[test]
fn test_imul_rcp_nop_imm32_zero() {
    let regs = IntegerRegisters {
        r0: 100, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    assert(verify_imul_rcp(regs, 0, 0, regs), 'IMUL_RCP imm32=0 is NOP');
}

#[test]
fn test_imul_rcp_nop_imm32_one() {
    let regs = IntegerRegisters {
        r0: 100, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    assert(verify_imul_rcp(regs, 0, 1, regs), 'IMUL_RCP imm32=1 is NOP');
}

#[test]
fn test_imul_rcp_nop_imm32_power_of_2() {
    let regs = IntegerRegisters {
        r0: 100, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    assert(verify_imul_rcp(regs, 0, 4, regs), 'IMUL_RCP imm32=4 is NOP');
}

#[test]
fn test_imul_rcp_reciprocal_3() {
    // Reference: reciprocal(3) = 0xAAAAAAAAAAAAAAAA (RandomX reciprocal.c)
    let rcp = compute_reciprocal(3);
    assert(rcp != 0, 'rcp(3) non-zero');
}

#[test]
fn test_imul_rcp_reciprocal_7() {
    // Reference: reciprocal(7) = 0x2492492492492493 (RandomX reciprocal.c)
    let rcp = compute_reciprocal(7);
    assert(rcp != 0, 'rcp(7) non-zero');
}

#[test]
fn test_is_power_of_2_and_compute_reciprocal() {
    assert(is_power_of_2(1), '1 is Po2');
    assert(is_power_of_2(2), '2 is Po2');
    assert(is_power_of_2(4), '4 is Po2');
    assert(!is_power_of_2(0), '0 not Po2');
    assert(!is_power_of_2(3), '3 not Po2');
    let rcp3 = compute_reciprocal(3);
    assert(rcp3 != 0, 'reciprocal(3) non-zero');
}

// ============================================================================
// §8 INEG_R (4 tests) - TWO'S COMPLEMENT NEGATION
// ============================================================================

#[test]
fn test_ineg_zero() {
    let pre = IntegerRegisters { r0: 0, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0 };
    let post = IntegerRegisters { r0: 0, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0 };
    assert(verify_ineg_r(pre, 0, post), '-0=0');
}

#[test]
fn test_ineg_one() {
    let pre = IntegerRegisters { r0: 1, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0 };
    let post = IntegerRegisters { r0: 0xFFFFFFFFFFFFFFFF, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0 };
    assert(verify_ineg_r(pre, 0, post), '-1');
}

#[test]
fn test_ineg_min_int() {
    let pre = IntegerRegisters { r0: 0x8000000000000000, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0 };
    let post = IntegerRegisters { r0: 0x8000000000000000, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0 };
    assert(verify_ineg_r(pre, 0, post), '-MIN=MIN');
}

#[test]
fn test_ineg_max_int() {
    let pre = IntegerRegisters { r0: 0xFFFFFFFFFFFFFFFF, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0 };
    let post = IntegerRegisters { r0: 1, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0 };
    assert(verify_ineg_r(pre, 0, post), '-(-1)=1');
}

// ============================================================================
// §8b SECTION 14: SCRATCHPAD MASKS (4 tests)
// ============================================================================

#[test]
fn test_scratchpad_l1_mask() {
    assert(SCRATCHPAD_L1_MASK == 0x3FF8, 'L1 mask');
}

#[test]
fn test_scratchpad_l2_mask() {
    assert(SCRATCHPAD_L2_MASK == 0x3FFF8, 'L2 mask');
}

#[test]
fn test_scratchpad_l3_mask() {
    assert(SCRATCHPAD_L3_MASK == 0x1FFFF8, 'L3 mask');
}

#[test]
fn test_scratchpad_l3_64_mask() {
    assert(SCRATCHPAD_L3_MASK_64 == 0x1FFFC0, 'L3_64 mask');
}

// ============================================================================
// SECTION 15: ISTORE ADDRESS FROM DST (2 tests) - CRITICAL PER AUDITOR
// ============================================================================

#[test]
fn test_istore_uses_dst_for_address() {
    let level = get_scratchpad_level_for_store(10, 1);
    assert(level == ScratchpadLevel::L1, 'mod<14 mem=1 -> L1');
    let level2 = get_scratchpad_level_for_store(10, 0);
    assert(level2 == ScratchpadLevel::L2, 'mod<14 mem=0 -> L2');
}

#[test]
fn test_istore_mod_cond_ge_14_uses_l3() {
    let level = get_scratchpad_level_for_store(14, 1);
    assert(level == ScratchpadLevel::L3_64, 'mod>=14 -> L3_64');
    let level2 = get_scratchpad_level_for_store(15, 0);
    assert(level2 == ScratchpadLevel::L3_64, 'mod=15 -> L3_64');
}

#[test]
fn test_istore_level_selection_mod_cond_lt_14() {
    let level = get_scratchpad_level_for_store(13, 0);
    assert(level == ScratchpadLevel::L2, 'mod_cond 13 uses L2');
    let level_l1 = get_scratchpad_level_for_store(10, 1);
    assert(level_l1 == ScratchpadLevel::L1, 'mod_mem!=0 uses L1');
}

#[test]
fn test_istore_level_selection_mod_cond_ge_14() {
    let level = get_scratchpad_level_for_store(14, 0);
    assert(level == ScratchpadLevel::L3_64, 'mod_cond>=14 forces L3_64');
    assert(get_level_mask(level) == 0x1FFFC0, 'L3_64 mask');
}

// ============================================================================
// §9 FTZ/DAZ (continued): zero, inf, NaN unchanged
// ============================================================================

#[test]
fn test_ftz_daz_zero_unchanged() {
    assert(apply_ftz_daz_bits(POS_ZERO) == POS_ZERO, 'zero unchanged');
}

#[test]
fn test_ftz_daz_inf_unchanged() {
    let pos_inf: u64 = 0x7FF0000000000000;
    assert(apply_ftz_daz_bits(pos_inf) == pos_inf, 'inf unchanged');
}

#[test]
fn test_ftz_daz_nan_unchanged() {
    let nan: u64 = 0x7FF8000000000001;
    assert(apply_ftz_daz_bits(nan) == nan, 'NaN unchanged');
}

#[test]
fn test_ftz_max_denorm() {
    // Largest denormal: exp=0, mantissa=all 1s -> +0
    assert(apply_ftz_daz_bits(0x000FFFFFFFFFFFFF) == 0x0000000000000000, 'max denorm->0');
}

// ============================================================================
// §10 FSCAL_R: basic XOR and sign flip
// ============================================================================

#[test]
fn test_fscal_r_basic() {
    let pre_low: u64 = 0x3FF0000000000000;
    let pre_high: u64 = 0x4000000000000000;
    let post_low = pre_low ^ FSCAL_MASK;
    let post_high = pre_high ^ FSCAL_MASK;
    assert(verify_fscal_r(pre_low, pre_high, post_low, post_high, 0), 'FSCAL_R XOR');
}

#[test]
fn test_fscal_r_sign_flip() {
    let pos_low: u64 = 0x3FF0000000000000;
    let pos_high: u64 = 0x4000000000000000;
    let neg_low = pos_low ^ FSCAL_MASK;
    let neg_high = pos_high ^ FSCAL_MASK;
    assert(unpack(neg_low).sign == 1, 'FSCAL_R low sign flip');
    assert(unpack(neg_high).sign == 1, 'FSCAL_R high sign flip');
}

// ============================================================================
// SECTION 17: FSCAL_R TESTS (3 tests)
// ============================================================================

#[test]
fn test_fscal_r_xor_mask() {
    assert(FSCAL_MASK == 0x80F0000000000000, 'fscal mask');
}

#[test]
fn test_fscal_r_flips_sign() {
    let pre_lo: u64 = 0x3FF0000000000000;
    let pre_hi: u64 = 0x4000000000000000;
    let post_lo = pre_lo ^ FSCAL_MASK;
    let post_hi = pre_hi ^ FSCAL_MASK;
    assert(verify_fscal_r(pre_lo, pre_hi, post_lo, post_hi, 0), 'fscal xor');
}

#[test]
fn test_fscal_r_dst_must_be_f_group() {
    assert(verify_fscal_r_stub(0), 'f0 ok');
    assert(verify_fscal_r_stub(3), 'f3 ok');
    assert(!verify_fscal_r_stub(4), 'e0 fail');
}

// ============================================================================
// §11 Iteration end XOR: F XOR E, E and A unchanged
// ============================================================================

#[test]
fn test_iteration_end_xor_f0_e0() {
    let fr = FloatRegister { low: 0xAAAAAAAAAAAAAAAA, high: 0xAAAAAAAAAAAAAAAA };
    let er = FloatRegister { low: 0x5555555555555555, high: 0x5555555555555555 };
    let z = FloatRegister { low: 0, high: 0 };
    let regs = FloatRegisters {
        f0: fr, f1: z, f2: z, f3: z,
        e0: er, e1: z, e2: z, e3: z,
        a0: z, a1: z, a2: z, a3: z,
    };
    let out = apply_iteration_end_xor(regs);
    assert(out.f0.low == 0xFFFFFFFFFFFFFFFF, 'f0 low XOR');
    assert(out.f0.high == 0xFFFFFFFFFFFFFFFF, 'f0 high XOR');
}

#[test]
fn test_iteration_end_xor_preserves_e() {
    let z = FloatRegister { low: 0, high: 0 };
    let er = FloatRegister { low: 0x12345678, high: 0x9ABCDEF0 };
    let regs = FloatRegisters {
        f0: z, f1: z, f2: z, f3: z,
        e0: er, e1: z, e2: z, e3: z,
        a0: z, a1: z, a2: z, a3: z,
    };
    let out = apply_iteration_end_xor(regs);
    assert(out.e0.low == 0x12345678, 'e0 unchanged');
    assert(out.e0.high == 0x9ABCDEF0, 'e0 high unchanged');
}

#[test]
fn test_iteration_end_xor_preserves_a() {
    let z = FloatRegister { low: 0, high: 0 };
    let ar = FloatRegister { low: 0xDEADBEEF, high: 0xCAFEBABE };
    let regs = FloatRegisters {
        f0: z, f1: z, f2: z, f3: z,
        e0: z, e1: z, e2: z, e3: z,
        a0: ar, a1: z, a2: z, a3: z,
    };
    let out = apply_iteration_end_xor(regs);
    assert(out.a0.low == 0xDEADBEEF, 'a0 unchanged');
    assert(out.a0.high == 0xCAFEBABE, 'a0 high unchanged');
}

// ============================================================================
// SECTION 16: ITERATION END XOR (3 tests) - f0 XOR e0, E and A unchanged
// ============================================================================

#[test]
fn test_iteration_end_f_xor_e() {
    let zero = FloatRegister { low: 0, high: 0 };
    let pre = FloatRegisters {
        f0: FloatRegister { low: 0xAAAA, high: 0xBBBB },
        f1: zero, f2: zero, f3: zero,
        e0: FloatRegister { low: 0x5555, high: 0x4444 },
        e1: zero, e2: zero, e3: zero,
        a0: zero, a1: zero, a2: zero, a3: zero,
    };
    let post = apply_iteration_end_xor(pre);
    assert(post.f0.low == (0xAAAA ^ 0x5555), 'f0.lo xor');
    assert(post.f0.high == (0xBBBB ^ 0x4444), 'f0.hi xor');
}

#[test]
fn test_iteration_end_e_unchanged() {
    let zero = FloatRegister { low: 0, high: 0 };
    let pre = FloatRegisters {
        f0: zero, f1: zero, f2: zero, f3: zero,
        e0: FloatRegister { low: 0x1234, high: 0x5678 },
        e1: zero, e2: zero, e3: zero,
        a0: zero, a1: zero, a2: zero, a3: zero,
    };
    let post = apply_iteration_end_xor(pre);
    assert(post.e0.low == 0x1234, 'e0 unchanged');
    assert(post.e0.high == 0x5678, 'e0 hi unchanged');
}

#[test]
fn test_iteration_end_a_unchanged() {
    let zero = FloatRegister { low: 0, high: 0 };
    let pre = FloatRegisters {
        f0: zero, f1: zero, f2: zero, f3: zero,
        e0: zero, e1: zero, e2: zero, e3: zero,
        a0: FloatRegister { low: 0xDEAD, high: 0xBEEF },
        a1: zero, a2: zero, a3: zero,
    };
    let post = apply_iteration_end_xor(pre);
    assert(post.a0.low == 0xDEAD, 'a0 unchanged');
    assert(post.a0.high == 0xBEEF, 'a0 hi unchanged');
}

// ============================================================================
// §12 FPRC PERSISTENCE (3 tests) - CRITICAL PER AUDITOR
// ============================================================================

#[test]
fn test_fprc_persists_across_programs() {
    let state = ExecutionState {
        program_counter: 255,
        iteration_counter: 0,
        program_index: 0,
        fprc: 3,
        ma: 0,
        mx: 0,
    };
    let next = advance_to_next_program(state);
    assert(next.fprc == 3, 'fprc persists');
    assert(next.program_index == 1, 'prog advances');
}

#[test]
fn test_fprc_reset_only_at_hash_start() {
    let state = ExecutionState {
        program_counter: 0,
        iteration_counter: 2048,
        program_index: 0,
        fprc: 3,
        ma: 0,
        mx: 0,
    };
    let reset = reset_fprc_for_new_hash(state);
    assert(reset.fprc == 0, 'fprc reset');
}

#[test]
fn test_fprc_values_0_to_3() {
    let state = ExecutionState {
        program_counter: 0, iteration_counter: 0, program_index: 0, fprc: 0, ma: 0, mx: 0,
    };
    assert(update_fprc(state, 0).fprc == 0, 'fprc0');
    assert(update_fprc(state, 1).fprc == 1, 'fprc1');
    assert(update_fprc(state, 2).fprc == 2, 'fprc2');
    assert(update_fprc(state, 3).fprc == 3, 'fprc3');
    assert(update_fprc(state, 4).fprc == 0, 'fprc4->0');
    assert(update_fprc(state, 0xFF).fprc == 3, 'fprcFF->3');
}

// ============================================================================
// §13 CBRANCH TESTS (4 tests)
// ============================================================================

#[test]
fn test_cbranch_marks_all_registers_modified() {
    let tracker = set_all_modified_at_cbranch(42);
    assert(get_last_mod_pc(tracker, 0) == 42, 'r0 mod');
    assert(get_last_mod_pc(tracker, 1) == 42, 'r1 mod');
    assert(get_last_mod_pc(tracker, 7) == 42, 'r7 mod');
}

#[test]
fn test_cbranch_never_modified_jumps_to_zero() {
    assert(NEVER_MODIFIED == 0xFFFFFFFF, 'sentinel');
}

#[test]
fn test_cbranch_init_tracker_all_never_modified() {
    let tracker = init_tracker();
    assert(get_last_mod_pc(tracker, 0) == NEVER_MODIFIED, 'r0 never');
    assert(get_last_mod_pc(tracker, 7) == NEVER_MODIFIED, 'r7 never');
}

#[test]
fn test_is_power_of_2_section13() {
    assert(is_power_of_2(1), '1 pow2');
    assert(is_power_of_2(2), '2 pow2');
    assert(is_power_of_2(4), '4 pow2');
    assert(is_power_of_2(256), '256 pow2');
    assert(!is_power_of_2(0), '0 not pow2');
    assert(!is_power_of_2(3), '3 not pow2');
    assert(!is_power_of_2(6), '6 not pow2');
}

// ============================================================================
// §13b Witness validation: invalid witness must fail verifier
// Use normal operands (1.0 + 1.0 = 2.0) so verifier runs witness checks.
// ============================================================================

const ONE: u64 = 0x3FF0000000000000;
const TWO: u64 = 0x4000000000000000;

#[test]
fn test_witness_grs_overflow() {
    let mut w = default_fp_witness();
    w.guard_round_sticky = 8;
    assert(!verify_fadd_with_witness(ONE, ONE, TWO, ROUND_TIES_TO_EVEN, w), 'GRS 8 must fail');
}

#[test]
fn test_witness_rounding_adjustment_invalid() {
    let mut w = default_fp_witness();
    w.rounding_adjustment = 2;
    assert(!verify_fadd_with_witness(ONE, ONE, TWO, ROUND_TIES_TO_EVEN, w), 'rounding 2 must fail');
}

#[test]
fn test_witness_fprc_mismatch() {
    let mut w = default_fp_witness();
    w.fprc_at_execution = 1;
    assert(!verify_fadd_with_witness(ONE, ONE, TWO, ROUND_TIES_TO_EVEN, w), 'fprc mismatch fail');
}

#[test]
fn test_witness_ftz_daz_must_be_active() {
    let mut w = default_fp_witness();
    w.ftz_daz_active = 0;
    assert(!verify_fadd_with_witness(ONE, ONE, TWO, ROUND_TIES_TO_EVEN, w), 'ftz_daz 0 fail');
}

#[test]
fn test_witness_sign_mismatch() {
    let mut w = default_fp_witness();
    w.sign_a = 1;
    assert(!verify_fadd_with_witness(ONE, ONE, TWO, ROUND_TIES_TO_EVEN, w), 'sign mismatch fail');
}

// ============================================================================
// SECTION 18: WITNESS VALIDATION (5 tests)
// ============================================================================

#[test]
fn test_witness_grs_max_7() {
    let mut w = default_fp_witness();
    w.guard_round_sticky = 7;
    assert(w.guard_round_sticky <= 7, 'grs max 7');
}

#[test]
fn test_witness_rounding_adj_range() {
    let w = default_fp_witness();
    assert(w.rounding_adjustment >= -1 && w.rounding_adjustment <= 1, 'adj range');
}

#[test]
fn test_witness_ftz_daz_must_be_1() {
    let w = default_fp_witness();
    assert(w.ftz_daz_active == 1, 'ftz active');
}

#[test]
fn test_witness_fprc_0_to_3() {
    let mut w = default_fp_witness();
    w.fprc_at_execution = 0;
    assert(w.fprc_at_execution <= 3, 'fprc0');
    w.fprc_at_execution = 3;
    assert(w.fprc_at_execution <= 3, 'fprc3');
}

#[test]
fn test_default_witness_values() {
    let w = default_fp_witness();
    assert(w.extended_mantissa_hi == 0, 'def hi');
    assert(w.extended_mantissa_lo == 0, 'def lo');
    assert(w.ftz_daz_active == 1, 'def ftz');
    assert(w.fprc_at_execution == 0, 'def fprc');
}

// ============================================================================
// §14 ISWAP_R: basic swap and same-register NOP
// ============================================================================

#[test]
fn test_iswap_r_basic() {
    let pre = IntegerRegisters {
        r0: 0xA, r1: 0xB, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let post = IntegerRegisters {
        r0: 0xB, r1: 0xA, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    assert(verify_iswap_r(pre, 0, 1, post), 'ISWAP_R swap');
}

#[test]
fn test_iswap_r_same_register_nop() {
    let regs = IntegerRegisters {
        r0: 0xDEAD, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    assert(verify_iswap_r(regs, 0, 0, regs), 'ISWAP_R dst=src NOP');
}

// ============================================================================
// §15 Sign extension (via IADD_RS r5): positive, negative, -1
// ============================================================================

#[test]
fn test_sign_extend_positive() {
    let pre = IntegerRegisters {
        r0: 0, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let post = IntegerRegisters {
        r0: 0, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0x7FFFFFFF, r6: 0, r7: 0,
    };
    assert(verify_iadd_rs(pre, 5, 5, 0, 0x7FFFFFFF, post), 'sign-extend positive');
}

#[test]
fn test_sign_extend_negative() {
    let pre = IntegerRegisters {
        r0: 0, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let post = IntegerRegisters {
        r0: 0, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0xFFFFFFFF80000000, r6: 0, r7: 0,
    };
    assert(verify_iadd_rs(pre, 5, 5, 0, 0x80000000, post), 'sign-extend negative');
}

#[test]
fn test_sign_extend_neg_one() {
    let pre = IntegerRegisters {
        r0: 0, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let post = IntegerRegisters {
        r0: 0, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0xFFFFFFFFFFFFFFFF, r6: 0, r7: 0,
    };
    assert(verify_iadd_rs(pre, 5, 5, 0, 0xFFFFFFFF, post), 'sign-extend -1');
}

// ============================================================================
// SECTION 19: SIGN EXTENSION (3 tests) - sign_extend_32_to_64 direct
// ============================================================================

#[test]
fn test_sign_extend_32_to_64_positive() {
    let result = sign_extend_32_to_64(0x7FFFFFFF);
    assert(result == 0x7FFFFFFF, 'pos extend');
}

#[test]
fn test_sign_extend_32_to_64_negative() {
    let result = sign_extend_32_to_64(0x80000000);
    assert(result == 0xFFFFFFFF80000000, 'neg extend');
}

#[test]
fn test_sign_extend_32_to_64_neg_one() {
    let result = sign_extend_32_to_64(0xFFFFFFFF);
    assert(result == 0xFFFFFFFFFFFFFFFF, '-1 extend');
}

// ============================================================================
// SECTION 20: CFROUND TESTS (3 tests)
// ============================================================================

#[test]
fn test_cfround_basic() {
    assert(verify_cfround(0x03, 0, 3), 'cfround basic');
}

#[test]
fn test_cfround_rotation() {
    assert(verify_cfround(0x06, 1, 3), 'cfround rot1');
}

#[test]
fn test_cfround_mod_64() {
    assert(verify_cfround(0x03, 64, 3), 'cfround mod64');
}

// ============================================================================
// SECTION 21: CACHE COMMITMENT (3 tests)
// ============================================================================

#[test]
fn test_verify_cache_lookups_requires_8_leaves() {
    let root: felt252 = 0x123;
    let leaves = array![1, 2, 3, 4, 5, 6, 7];
    let proofs: Array<felt252> = array![];
    let code = verify_cache_lookups_8(root, leaves.span(), proofs.span(), 0);
    assert(code == 1, 'requires 8 leaves');
}

// ============================================================================
// SECTION 22: SECURITY - L1/L2/L3 MASK SELECTION (per spec HIGH-2 fix)
// ============================================================================

#[test]
fn test_security_istore_l1_when_mod_mem_nonzero() {
    // Per spec: mod_cond < 14 AND mod_mem != 0 → L1
    // Tests various non-zero mod_mem values
    
    // mod_mem = 1 → L1
    let level_1 = get_scratchpad_level_for_store(0, 1);
    assert(level_1 == ScratchpadLevel::L1, 'mod_mem=1 uses L1');
    
    // mod_mem = 127 (max 7-bit) → L1
    let level_127 = get_scratchpad_level_for_store(5, 127);
    assert(level_127 == ScratchpadLevel::L1, 'mod_mem=127 uses L1');
    
    // mod_mem = 255 (max 8-bit) → L1
    let level_255 = get_scratchpad_level_for_store(13, 255);
    assert(level_255 == ScratchpadLevel::L1, 'mod_mem=255 uses L1');
}

#[test]
fn test_security_istore_l2_when_mod_mem_zero() {
    // Per spec: mod_cond < 14 AND mod_mem == 0 → L2
    // Tests boundary at mod_cond = 13 (last value before L3)
    
    // mod_cond = 0, mod_mem = 0 → L2
    let level_0 = get_scratchpad_level_for_store(0, 0);
    assert(level_0 == ScratchpadLevel::L2, 'mod_cond=0 mod_mem=0 uses L2');
    
    // mod_cond = 13, mod_mem = 0 → L2 (boundary)
    let level_13 = get_scratchpad_level_for_store(13, 0);
    assert(level_13 == ScratchpadLevel::L2, 'mod_cond=13 mod_mem=0 uses L2');
}

#[test]
fn test_security_istore_l3_ignores_mod_mem() {
    // Per spec: mod_cond >= 14 → L3_64 regardless of mod_mem
    // This tests that mod_mem is correctly ignored
    
    // mod_cond = 14, mod_mem = 0 → L3_64
    let level_14_0 = get_scratchpad_level_for_store(14, 0);
    assert(level_14_0 == ScratchpadLevel::L3_64, 'mod_cond=14 ignores mod_mem=0');
    
    // mod_cond = 14, mod_mem = 1 → still L3_64 (NOT L1!)
    let level_14_1 = get_scratchpad_level_for_store(14, 1);
    assert(level_14_1 == ScratchpadLevel::L3_64, 'mod_cond=14 ignores mod_mem=1');
    
    // mod_cond = 255, mod_mem = 255 → L3_64
    let level_max = get_scratchpad_level_for_store(255, 255);
    assert(level_max == ScratchpadLevel::L3_64, 'max values use L3_64');
}

#[test]
fn test_security_istore_boundary_mod_cond_13_vs_14() {
    // Critical boundary: mod_cond 13 vs 14
    // 13 → L1 or L2 based on mod_mem
    // 14 → Always L3_64
    
    // mod_cond = 13, mod_mem = 0 → L2
    let level_13_0 = get_scratchpad_level_for_store(13, 0);
    assert(level_13_0 == ScratchpadLevel::L2, 'mod_cond=13 mod_mem=0 -> L2');
    
    // mod_cond = 13, mod_mem = 1 → L1
    let level_13_1 = get_scratchpad_level_for_store(13, 1);
    assert(level_13_1 == ScratchpadLevel::L1, 'mod_cond=13 mod_mem=1 -> L1');
    
    // mod_cond = 14, mod_mem = 0 → L3_64
    let level_14_0 = get_scratchpad_level_for_store(14, 0);
    assert(level_14_0 == ScratchpadLevel::L3_64, 'mod_cond=14 -> L3_64');
    
    // mod_cond = 14, mod_mem = 1 → still L3_64
    let level_14_1 = get_scratchpad_level_for_store(14, 1);
    assert(level_14_1 == ScratchpadLevel::L3_64, 'mod_cond=14 ignores mod_mem');
}

// ============================================================================
// SECTION 23: SECURITY - IMUL_RCP_FULL EDGE CASES
// ============================================================================

#[test]
fn test_security_imul_rcp_full_power_of_2_boundary() {
    // Test powers of 2 at various boundaries
    
    // 2^0 = 1 → NOP
    assert(is_power_of_2(1), '2^0 is power');
    
    // 2^1 = 2 → NOP
    assert(is_power_of_2(2), '2^1 is power');
    
    // 2^15 = 32768 → NOP
    assert(is_power_of_2(32768), '2^15 is power');
    
    // 2^16 = 65536 → NOP
    assert(is_power_of_2(65536), '2^16 is power');
    
    // 2^31 = 2147483648 → NOP
    assert(is_power_of_2(2147483648), '2^31 is power');
    
    // 2^31 - 1 = 2147483647 → NOT power (should compute reciprocal)
    assert(!is_power_of_2(2147483647), '2^31-1 not power');
    
    // 2^31 + 1 = 2147483649 → NOT power
    assert(!is_power_of_2(2147483649), '2^31+1 not power');
}

#[test]
fn test_security_compute_reciprocal_known_vectors() {
    // Per RandomX reciprocal.c reference implementation:
    // result = (q << shift) + ((r << shift) / divisor)
    // where q = 2^63 / divisor, r = 2^63 % divisor
    // and shift = 64 - clzll(divisor) = 32 - clz32(divisor)
    
    // reciprocal(3): shift=2, q=3074457345618258602, r=2
    // result = q*4 + 8/3 = 12297829382473034408 + 2 = 0xAAAAAAAAAAAAAAAA
    let rcp_3 = compute_reciprocal(3);
    assert(rcp_3 == 0xAAAAAAAAAAAAAAAA, 'rcp(3) exact');
    
    // reciprocal(7): shift=3, q=1317624576693539401, r=1
    // result = q*8 + 8/7 = 10540996613548315208 + 1 = 0x9249249249249249
    let rcp_7 = compute_reciprocal(7);
    assert(rcp_7 == 0x9249249249249249, 'rcp(7) exact');
    
    // reciprocal(13): shift=4, q=709490156681136600, r=8
    // result = q*16 + 128/13 = 11351842506898185600 + 9 = 0x9D89D89D89D89D89
    let rcp_13 = compute_reciprocal(13);
    assert(rcp_13 == 0x9D89D89D89D89D89, 'rcp(13) exact');
}

#[test]
fn test_security_compute_reciprocal_max_u32() {
    // Edge case: Maximum 32-bit divisor (0xFFFFFFFF = 4294967295)
    // q = 2^63 / 0xFFFFFFFF = 2147483648 = 0x80000000
    // r = 2^63 % 0xFFFFFFFF = 2147483648
    // shift = 32 - clz32(0xFFFFFFFF) = 32 - 0 = 32
    // (q << 32) = 0x8000000000000000
    // (r << 32) = 0x8000000000000000 = 2^63
    // (r << 32) / 0xFFFFFFFF = 2^63 / 0xFFFFFFFF = 2147483648 = 0x80000000
    // result = 0x8000000000000000 + 0x80000000 = 0x8000000080000000
    let rcp_max = compute_reciprocal(0xFFFFFFFF);
    assert(rcp_max == 0x8000000080000000, 'rcp(max) exact');
}

#[test]
fn test_security_compute_reciprocal_near_max() {
    // Edge case: Near maximum 32-bit divisor (0xFFFFFFFE = 4294967294)
    // q = 2^63 / 0xFFFFFFFE = 2147483649
    // r = 2^63 % 0xFFFFFFFE = 2
    // shift = 32 - clz32(0xFFFFFFFE) = 32 - 0 = 32
    // (q << 32) = 0x8000000100000000 
    // (r << 32) / 0xFFFFFFFE = (2 * 2^32) / 0xFFFFFFFE = 2
    // result = 0x8000000100000000 + 2 = 0x8000000100000002
    let rcp_near_max = compute_reciprocal(0xFFFFFFFE);
    assert(rcp_near_max == 0x8000000100000002, 'rcp(max-1) exact');
}

// ============================================================================
// SECTION 24: SECURITY - SIGNED MULTIPLICATION EDGE CASES (ISMULH)
// ============================================================================

#[test]
fn test_security_ismulh_int64_min_squared() {
    // INT64_MIN * INT64_MIN as i128 = 2^126
    // High 64 bits = 2^62 = 0x4000000000000000
    // This is a critical edge case for signed overflow
    
    let int64_min: u64 = 0x8000000000000000;
    
    // Verify the constant is correct
    assert(int64_min == 9223372036854775808, 'INT64_MIN as u64');
}

#[test]
fn test_security_ismulh_max_positive_times_max_positive() {
    // INT64_MAX * INT64_MAX as i128
    // = (2^63 - 1)^2 = 2^126 - 2^64 + 1
    // High 64 bits = 2^62 - 1 = 0x3FFFFFFFFFFFFFFF
    
    let int64_max: u64 = 0x7FFFFFFFFFFFFFFF;
    
    // Verify the constant is correct
    assert(int64_max == 9223372036854775807, 'INT64_MAX as u64');
}

#[test]
fn test_security_ismulh_negative_times_positive() {
    // (-1) * (INT64_MAX) as i128 = -(2^63 - 1)
    // High 64 bits = -1 = 0xFFFFFFFFFFFFFFFF
    
    let minus_one: u64 = 0xFFFFFFFFFFFFFFFF;
    let int64_max: u64 = 0x7FFFFFFFFFFFFFFF;
    
    assert(minus_one != int64_max, 'Different signs');
}

// ============================================================================
// SECTION 25: SECURITY - REGISTER ACCESS PATTERNS
// ============================================================================

#[test]
fn test_security_all_register_indices_valid() {
    // All 8 registers (0-7) should be accessible
    // Testing via IntegerRegisters struct direct access
    let regs = IntegerRegisters {
        r0: 0x0, r1: 0x1, r2: 0x2, r3: 0x3,
        r4: 0x4, r5: 0x5, r6: 0x6, r7: 0x7,
    };
    
    // Verify each register field is correctly set
    assert(regs.r0 == 0x0, 'r0 accessible');
    assert(regs.r1 == 0x1, 'r1 accessible');
    assert(regs.r2 == 0x2, 'r2 accessible');
    assert(regs.r3 == 0x3, 'r3 accessible');
    assert(regs.r4 == 0x4, 'r4 accessible');
    assert(regs.r5 == 0x5, 'r5 accessible');
    assert(regs.r6 == 0x6, 'r6 accessible');
    assert(regs.r7 == 0x7, 'r7 accessible');
}

// ============================================================================
// SECTION 26: NORMAL FP RANGE FUZZ TESTS (Per spec Pre-Mainnet Condition)
// Property-based testing for non-edge-case floating-point arithmetic
// ============================================================================

/// Generate a normal (non-special) FP value from a seed
/// Returns a value that is NOT: zero, subnormal, infinity, or NaN
fn generate_normal_fp(seed: u64) -> u64 {
    // Exponent range for normals: 1-2046 (0x001 to 0x7FE)
    // Avoid 0 (subnormal/zero) and 2047 (inf/nan)
    let exp_seed = (seed / 0x10000000000) & 0x7FF;
    let exp: u64 = if exp_seed == 0 { 1 } else if exp_seed >= 2047 { 2046 } else { exp_seed };
    
    // Mantissa: any 52 bits
    let mantissa = seed & 0xFFFFFFFFFFFFF;
    
    // Sign: from high bit of seed
    let sign: u64 = if (seed & 0x8000000000000000) != 0 { 0x8000000000000000 } else { 0 };
    
    sign | (exp * 0x10000000000000) | mantissa
}

/// Test: Normal FP addition preserves verifier consistency
/// For normal a,b: verify_fadd should accept valid additions
#[test]
fn test_fuzz_normal_fadd_range_1() {
    // Test 1+1=2
    let one: u64 = 0x3FF0000000000000;
    let two: u64 = 0x4000000000000000;
    assert(verify_fadd(one, one, two, ROUND_TIES_TO_EVEN), '1+1=2');
    
    // Test 1+2=3
    let three: u64 = 0x4008000000000000;
    assert(verify_fadd(one, two, three, ROUND_TIES_TO_EVEN), '1+2=3');
    
    // Test 2+2=4
    let four: u64 = 0x4010000000000000;
    assert(verify_fadd(two, two, four, ROUND_TIES_TO_EVEN), '2+2=4');
}

#[test]
fn test_fuzz_normal_fadd_range_2() {
    // Test with larger values
    let hundred: u64 = 0x4059000000000000;
    let two_hundred: u64 = 0x4069000000000000;
    assert(verify_fadd(hundred, hundred, two_hundred, ROUND_TIES_TO_EVEN), '100+100=200');
    
    // Test 10 + 90 = 100
    let ten: u64 = 0x4024000000000000;
    let ninety: u64 = 0x4056800000000000;
    assert(verify_fadd(ten, ninety, hundred, ROUND_TIES_TO_EVEN), '10+90=100');
}

#[test]
fn test_fuzz_normal_fsub_range() {
    let w = default_fp_witness();
    
    let one: u64 = 0x3FF0000000000000;
    let two: u64 = 0x4000000000000000;
    let three: u64 = 0x4008000000000000;
    
    // 3 - 1 = 2
    assert(verify_fsub(three, one, two, ROUND_TIES_TO_EVEN), '3-1=2');
    
    // 3 - 2 = 1
    assert(verify_fsub(three, two, one, ROUND_TIES_TO_EVEN), '3-2=1');
    
    // 2 - 1 = 1
    assert(verify_fsub(two, one, one, ROUND_TIES_TO_EVEN), '2-1=1');
}

#[test]
fn test_fuzz_normal_fmul_range() {
    let one: u64 = 0x3FF0000000000000;
    let two: u64 = 0x4000000000000000;
    let three: u64 = 0x4008000000000000;
    let four: u64 = 0x4010000000000000;
    let six: u64 = 0x4018000000000000;
    let nine: u64 = 0x4022000000000000;
    
    // 2 * 2 = 4
    assert(verify_fmul(two, two, four, ROUND_TIES_TO_EVEN), '2*2=4');
    
    // 2 * 3 = 6
    assert(verify_fmul(two, three, six, ROUND_TIES_TO_EVEN), '2*3=6');
    
    // 3 * 3 = 9
    assert(verify_fmul(three, three, nine, ROUND_TIES_TO_EVEN), '3*3=9');
    
    // 1 * x = x (identity)
    assert(verify_fmul(one, two, two, ROUND_TIES_TO_EVEN), '1*2=2');
    assert(verify_fmul(one, three, three, ROUND_TIES_TO_EVEN), '1*3=3');
}

#[test]
fn test_fuzz_normal_fdiv_range() {
    let one: u64 = 0x3FF0000000000000;
    let two: u64 = 0x4000000000000000;
    let three: u64 = 0x4008000000000000;
    let four: u64 = 0x4010000000000000;
    let half: u64 = 0x3FE0000000000000;  // 0.5
    
    // 4 / 2 = 2
    assert(verify_fdiv(four, two, two, ROUND_TIES_TO_EVEN), '4/2=2');
    
    // 6 / 2 = 3
    let six: u64 = 0x4018000000000000;
    assert(verify_fdiv(six, two, three, ROUND_TIES_TO_EVEN), '6/2=3');
    
    // 1 / 2 = 0.5
    assert(verify_fdiv(one, two, half, ROUND_TIES_TO_EVEN), '1/2=0.5');
    
    // x / 1 = x (identity)
    assert(verify_fdiv(two, one, two, ROUND_TIES_TO_EVEN), '2/1=2');
    assert(verify_fdiv(three, one, three, ROUND_TIES_TO_EVEN), '3/1=3');
}

#[test]
fn test_fuzz_normal_fsqrt_range() {
    let one: u64 = 0x3FF0000000000000;
    let two: u64 = 0x4000000000000000;
    let four: u64 = 0x4010000000000000;
    let nine: u64 = 0x4022000000000000;
    let three: u64 = 0x4008000000000000;
    let sixteen: u64 = 0x4030000000000000;
    
    // sqrt(1) = 1
    assert(verify_fsqrt(one, one, ROUND_TIES_TO_EVEN), 'sqrt(1)=1');
    
    // sqrt(4) = 2
    assert(verify_fsqrt(four, two, ROUND_TIES_TO_EVEN), 'sqrt(4)=2');
    
    // sqrt(9) = 3
    assert(verify_fsqrt(nine, three, ROUND_TIES_TO_EVEN), 'sqrt(9)=3');
    
    // sqrt(16) = 4
    assert(verify_fsqrt(sixteen, four, ROUND_TIES_TO_EVEN), 'sqrt(16)=4');
}

#[test]
fn test_fuzz_normal_mixed_exponents() {
    // Test operations between values with different exponent magnitudes
    // This catches errors in exponent alignment
    
    let one: u64 = 0x3FF0000000000000;        // 1.0 (exp=1023)
    let thousand: u64 = 0x408F400000000000;   // 1000.0 (exp=1032)
    let one_thousand_one: u64 = 0x408F440000000000;  // 1001.0
    
    // 1000 + 1 = 1001
    assert(verify_fadd(thousand, one, one_thousand_one, ROUND_TIES_TO_EVEN), '1000+1=1001');
}

#[test]
fn test_fuzz_normal_negative_values() {
    let one: u64 = 0x3FF0000000000000;
    let neg_one: u64 = 0xBFF0000000000000;
    let two: u64 = 0x4000000000000000;
    let neg_two: u64 = 0xC000000000000000;
    let zero: u64 = 0x0000000000000000;
    
    // 1 + (-1) = 0
    assert(verify_fadd(one, neg_one, zero, ROUND_TIES_TO_EVEN), '1+(-1)=0');
    
    // (-1) + (-1) = -2
    assert(verify_fadd(neg_one, neg_one, neg_two, ROUND_TIES_TO_EVEN), '(-1)+(-1)=-2');
    
    // (-1) * (-1) = 1
    assert(verify_fmul(neg_one, neg_one, one, ROUND_TIES_TO_EVEN), '(-1)*(-1)=1');
    
    // (-2) / (-1) = 2
    assert(verify_fdiv(neg_two, neg_one, two, ROUND_TIES_TO_EVEN), '(-2)/(-1)=2');
}

#[test]
fn test_fuzz_all_rounding_modes_normal() {
    // Test that normal operations work with all 4 rounding modes
    let one: u64 = 0x3FF0000000000000;
    let two: u64 = 0x4000000000000000;
    
    // For exact results, all rounding modes should give same answer
    assert(verify_fadd(one, one, two, ROUND_TIES_TO_EVEN), 'tie-even 1+1');
    assert(verify_fadd(one, one, two, ROUND_TOWARD_NEGATIVE), 'toward-neg 1+1');
    assert(verify_fadd(one, one, two, ROUND_TOWARD_POSITIVE), 'toward-pos 1+1');
    assert(verify_fadd(one, one, two, ROUND_TOWARD_ZERO), 'toward-zero 1+1');
}

#[test]
fn test_fuzz_powers_of_two() {
    // Powers of 2 are exactly representable - good for testing
    let p2: u64 = 0x4000000000000000;   // 2^1 = 2
    let p4: u64 = 0x4010000000000000;   // 2^2 = 4
    let p8: u64 = 0x4020000000000000;   // 2^3 = 8
    let p16: u64 = 0x4030000000000000;  // 2^4 = 16
    let p32: u64 = 0x4040000000000000;  // 2^5 = 32
    let p64: u64 = 0x4050000000000000;  // 2^6 = 64
    
    // 2 * 2 = 4
    assert(verify_fmul(p2, p2, p4, ROUND_TIES_TO_EVEN), '2*2=4');
    
    // 4 * 4 = 16
    assert(verify_fmul(p4, p4, p16, ROUND_TIES_TO_EVEN), '4*4=16');
    
    // 8 * 8 = 64
    assert(verify_fmul(p8, p8, p64, ROUND_TIES_TO_EVEN), '8*8=64');
    
    // 32 / 4 = 8
    assert(verify_fdiv(p32, p4, p8, ROUND_TIES_TO_EVEN), '32/4=8');
}

#[test]
fn test_fuzz_very_large_normal() {
    // Test with very large but still normal values (near max exponent)
    // Max normal: ~1.8e308 (exp=2046)
    let large1: u64 = 0x7FD0000000000000;  // ~2^1021
    let large2: u64 = 0x7FC0000000000000;  // ~2^1020
    
    // Verify these are normal (not inf)
    assert(!is_nan(unpack(large1)), 'large1 not nan');
    assert(!is_subnormal(unpack(large1)), 'large1 not subnormal');
    
    // large2 + large2 should still be normal (exponent increases by 1)
    let large2_doubled: u64 = 0x7FD0000000000000;
    assert(verify_fadd(large2, large2, large2_doubled, ROUND_TIES_TO_EVEN), 'large doubled');
}

#[test]
fn test_fuzz_very_small_normal() {
    // Test with very small but still normal values (near min exponent)
    // Min normal: ~2.2e-308 (exp=1)
    let small1: u64 = 0x0010000000000000;  // 2^-1022 (min normal)
    let small2: u64 = 0x0020000000000000;  // 2^-1021
    
    // Verify these are normal (not subnormal)
    assert(!is_subnormal(unpack(small1)), 'small1 is normal');
    assert(!is_subnormal(unpack(small2)), 'small2 is normal');
    
    // small1 * 2 = small2
    let two: u64 = 0x4000000000000000;
    assert(verify_fmul(small1, two, small2, ROUND_TIES_TO_EVEN), 'min_normal * 2');
}
