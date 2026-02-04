use monero_vm::randomx::fraud_proof::ieee754::{
    default_fp_witness, verify_fdiv_with_witness, verify_fadd_with_witness,
    ROUND_TIES_TO_EVEN, ROUND_TOWARD_NEGATIVE
};

#[test]
fn test_canonical_fdiv_vectors() {
    // zero_dividend
    let w0 = default_fp_witness();
    assert(verify_fdiv_with_witness(0x0000000000000000, 0x3FF0000000000000, 0x0000000000000000, 0, w0), 'zero_dividend');

    // self_division (3.0 / 3.0 = 1.0)
    let w1 = default_fp_witness();
    assert(verify_fdiv_with_witness(0x4008000000000000, 0x4008000000000000, 0x3FF0000000000000, 0, w1), 'self_division');

    // near_zero_divisor_min_e_group (max finite / min divisor -> +inf)
    let w2 = default_fp_witness();
    assert(verify_fdiv_with_witness(0x7FEFFFFFFFFFFFFF, 0x3000000000000001, 0x7FF0000000000000, 0, w2), 'near_zero_divisor');
}

#[test]
fn test_canonical_fadd_signed_zero_vectors() {
    let w0 = default_fp_witness();
    assert(verify_fadd_with_witness(0x0000000000000000, 0x8000000000000000, 0x8000000000000000, ROUND_TOWARD_NEGATIVE, w0), 'round_down_signed_zero');

    let w1 = default_fp_witness();
    assert(verify_fadd_with_witness(0x0000000000000000, 0x8000000000000000, 0x0000000000000000, ROUND_TIES_TO_EVEN, w1), 'ties_even_signed_zero');
}
