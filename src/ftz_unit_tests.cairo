//! Focused FTZ/DAZ unit tests to avoid compiling the large integration suite.

use monero_vm::randomx::fraud_proof::ieee754::{
    apply_ftz_daz_bits,
    verify_fadd_with_witness,
    verify_fmul_with_witness,
    verify_fdiv_with_witness,
    verify_fsqrt_with_witness,
    default_fp_witness,
};

#[test]
fn test_apply_ftz_daz_flushes_denormals() {
    let pos_denorm: u64 = 0x0000000000000001;
    let neg_denorm: u64 = 0x8000000000000001;
    let pos_zero: u64 = 0x0000000000000000;
    let neg_zero: u64 = 0x8000000000000000;

    assert(apply_ftz_daz_bits(pos_denorm) == pos_zero, 'pos denorm -> +0');
    assert(apply_ftz_daz_bits(neg_denorm) == neg_zero, 'neg denorm -> -0');
}

#[test]
fn test_ftz_daz_in_fadd_with_witness() {
    let witness = default_fp_witness();
    let denorm: u64 = 0x0000000000000001;
    let one: u64 = 0x3FF0000000000000;
    let result: u64 = 0x3FF0000000000000;
    assert(verify_fadd_with_witness(denorm, one, result, 0, witness), 'denorm + 1.0 = 1.0');
}

#[test]
fn test_ftz_daz_in_fsub_with_witness() {
    let witness = default_fp_witness();
    let one: u64 = 0x3FF0000000000000;
    let denorm: u64 = 0x0000000000000001;
    let result: u64 = 0x3FF0000000000000;
    assert(verify_fadd_with_witness(one, denorm, result, 0, witness), '1.0 + denorm = 1.0');
}

#[test]
fn test_ftz_daz_in_fmul_with_witness() {
    let witness = default_fp_witness();
    let denorm: u64 = 0x0000000000000001;
    let one: u64 = 0x3FF0000000000000;
    let zero: u64 = 0x0000000000000000;
    assert(verify_fmul_with_witness(denorm, one, zero, 0, witness), 'denorm * 1.0 = 0.0');
}

#[test]
fn test_ftz_daz_in_fdiv_with_witness() {
    let witness = default_fp_witness();
    let one: u64 = 0x3FF0000000000000;
    let denorm: u64 = 0x0000000000000001;
    let inf: u64 = 0x7FF0000000000000;
    assert(verify_fdiv_with_witness(one, denorm, inf, 0, witness), '1.0 / denorm = inf');
}

#[test]
fn test_ftz_daz_in_fsqrt_with_witness() {
    let witness = default_fp_witness();
    let denorm: u64 = 0x0000000000000001;
    let zero: u64 = 0x0000000000000000;
    assert(verify_fsqrt_with_witness(denorm, zero, 0, witness), 'sqrt(denorm) = 0.0');
}
