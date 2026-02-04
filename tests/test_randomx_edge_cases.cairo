// FP-only edge-case tests for RandomX verifier (M2 scope)
// Spec references: RandomX spec 4.3, 4.3.2, 5.4.1

use monero_vm::randomx::fraud_proof::fp_stubs::{
    verify_fscal_r, FSCAL_MASK
};
use monero_vm::randomx::fraud_proof::ieee754::{
    unpack, is_nan, is_subnormal,
    apply_ftz_daz_bits, verify_fadd_with_witness, verify_fsub, verify_fdiv,
    verify_cfround, verify_e_group_invariant,
    verify_e_group_exponent_full, verify_f_group_invariant,
    compute_e_mask, apply_e_group_mask, default_fp_witness,
    ROUND_TIES_TO_EVEN, ROUND_TOWARD_NEGATIVE, ROUND_TOWARD_POSITIVE, ROUND_TOWARD_ZERO
};

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
