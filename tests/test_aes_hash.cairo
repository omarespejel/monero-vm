// ============================================================
// Tests for AesHash1R Implementation
// ============================================================

use monero_vm::randomx::aes_hash::{
    AesHash1RState,
    aes_state_from_bytes, aes_state_to_bytes,
    aes_enc_round, aes_dec_round,
    aes_hash_process_block, aes_hash_finalize,
    aes_hash_state_to_bytes, aes_hash_1r,
    get_aes_hash_initial_state, get_aes_hash_extra_keys,
};

// ============================================================
// AES State Tests
// ============================================================

#[test]
fn test_aes_state_from_bytes() {
    let bytes: Array<u8> = array![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    
    let state = aes_state_from_bytes(bytes.span());
    
    // Column-major order
    assert(state.s00 == 0x00, 's00');
    assert(state.s10 == 0x01, 's10');
    assert(state.s20 == 0x02, 's20');
    assert(state.s30 == 0x03, 's30');
    assert(state.s03 == 0x0c, 's03');
}

#[test]
fn test_aes_state_roundtrip() {
    let bytes: Array<u8> = array![
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    ];
    
    let state = aes_state_from_bytes(bytes.span());
    let result = aes_state_to_bytes(state);
    
    assert(*result.at(0) == 0x32, 'byte 0');
    assert(*result.at(15) == 0x34, 'byte 15');
    assert(result.len() == 16, 'length');
}

// ============================================================
// Initial State Tests
// ============================================================

#[test]
fn test_initial_state_values() {
    let (s0, s1, s2, s3) = get_aes_hash_initial_state();
    
    // state0 = 0d 2c b5 92 de 56 a8 9f 47 db 82 cc ad 3a 98 d7
    assert(s0.s00 == 0x0d, 's0.s00');
    assert(s0.s10 == 0x2c, 's0.s10');
    assert(s0.s33 == 0xd7, 's0.s33');
    
    // state1 = 6e 99 8d 33 98 b7 c7 15 5a 12 9e f5 57 80 e7 ac
    assert(s1.s00 == 0x6e, 's1.s00');
    
    // state2 = 17 00 77 6a d0 c7 62 ae 6b 50 79 50 e4 7c a0 e8
    assert(s2.s00 == 0x17, 's2.s00');
    
    // state3 = 0c 24 0a 63 8d 82 ad 07 05 00 a1 79 48 49 99 7e
    assert(s3.s00 == 0x0c, 's3.s00');
}

#[test]
fn test_extra_keys_values() {
    let (xkey0, xkey1) = get_aes_hash_extra_keys();
    
    // xkey0 = 89 83 fa f6 9f 94 24 8b bf 56 dc 90 01 02 89 06
    assert(xkey0.s00 == 0x89, 'xkey0.s00');
    assert(xkey0.s10 == 0x83, 'xkey0.s10');
    
    // xkey1 = d1 63 b2 61 3c e0 f4 51 c6 43 10 ee 9b f9 18 ed
    assert(xkey1.s00 == 0xd1, 'xkey1.s00');
}

// ============================================================
// AES Round Tests
// ============================================================

#[test]
fn test_aes_enc_round_not_identity() {
    let state = aes_state_from_bytes(array![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ].span());
    
    let key = aes_state_from_bytes(array![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ].span());
    
    let result = aes_enc_round(state, key);
    
    // Result should be different from input
    assert(result.s00 != state.s00, 'not identity');
}

#[test]
fn test_aes_dec_round_not_identity() {
    let state = aes_state_from_bytes(array![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ].span());
    
    let key = aes_state_from_bytes(array![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ].span());
    
    let result = aes_dec_round(state, key);
    
    // Result should be different from input
    assert(result.s00 != state.s00, 'not identity');
}

#[test]
fn test_enc_dec_produce_different_results() {
    let state = aes_state_from_bytes(array![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ].span());
    
    let key = aes_state_from_bytes(array![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ].span());
    
    let enc_result = aes_enc_round(state, key);
    let dec_result = aes_dec_round(state, key);
    
    // Enc and dec should produce different results
    assert(enc_result.s00 != dec_result.s00, 'enc != dec');
}

// ============================================================
// AesHash1R Block Processing Tests
// ============================================================

#[test]
fn test_process_block_changes_state() {
    let (s0, s1, s2, s3) = get_aes_hash_initial_state();
    let state = AesHash1RState { col0: s0, col1: s1, col2: s2, col3: s3 };
    
    // Create a 64-byte block of zeros
    let mut block: Array<u8> = ArrayTrait::new();
    let mut i: usize = 0;
    loop {
        if i >= 64 { break; }
        block.append(0);
        i += 1;
    }
    
    let new_state = aes_hash_process_block(state, block.span());
    
    // State should have changed
    assert(new_state.col0.s00 != s0.s00, 'col0 changed');
}

#[test]
fn test_process_block_deterministic() {
    let (s0, s1, s2, s3) = get_aes_hash_initial_state();
    let state1 = AesHash1RState { col0: s0, col1: s1, col2: s2, col3: s3 };
    
    let (s0_2, s1_2, s2_2, s3_2) = get_aes_hash_initial_state();
    let state2 = AesHash1RState { col0: s0_2, col1: s1_2, col2: s2_2, col3: s3_2 };
    
    let mut block: Array<u8> = ArrayTrait::new();
    let mut i: usize = 0;
    loop {
        if i >= 64 { break; }
        block.append((i % 256).try_into().unwrap());
        i += 1;
    }
    
    let result1 = aes_hash_process_block(state1, block.span());
    let result2 = aes_hash_process_block(state2, block.span());
    
    assert(result1.col0.s00 == result2.col0.s00, 'deterministic');
}

// ============================================================
// AesHash1R Output Tests
// ============================================================

#[test]
fn test_aes_hash_output_size() {
    // Create a small test input (64 bytes = 1 block)
    let mut input: Array<u8> = ArrayTrait::new();
    let mut i: usize = 0;
    loop {
        if i >= 64 { break; }
        input.append(0);
        i += 1;
    }
    
    let result = aes_hash_1r(input.span());
    
    // Output should be 64 bytes
    assert(result.len() == 64, 'output 64 bytes');
}

#[test]
fn test_aes_hash_different_inputs() {
    // Input 1: all zeros
    let mut input1: Array<u8> = ArrayTrait::new();
    let mut i: usize = 0;
    loop {
        if i >= 64 { break; }
        input1.append(0);
        i += 1;
    }
    
    // Input 2: all ones
    let mut input2: Array<u8> = ArrayTrait::new();
    let mut i: usize = 0;
    loop {
        if i >= 64 { break; }
        input2.append(1);
        i += 1;
    }
    
    let result1 = aes_hash_1r(input1.span());
    let result2 = aes_hash_1r(input2.span());
    
    // Different inputs should produce different outputs
    assert(*result1.at(0) != *result2.at(0), 'diff input diff out');
}

#[test]
fn test_aes_hash_multi_block() {
    // Create a 128-byte input (2 blocks)
    let mut input: Array<u8> = ArrayTrait::new();
    let mut i: usize = 0;
    loop {
        if i >= 128 { break; }
        input.append((i % 256).try_into().unwrap());
        i += 1;
    }
    
    let result = aes_hash_1r(input.span());
    assert(result.len() == 64, '64 byte output');
}

// ============================================================
// AesHash1R Finalization Tests
// ============================================================

#[test]
fn test_finalization_changes_state() {
    let (s0, s1, s2, s3) = get_aes_hash_initial_state();
    let state = AesHash1RState { col0: s0, col1: s1, col2: s2, col3: s3 };
    
    let finalized = aes_hash_finalize(state);
    
    // Finalization should change the state
    assert(finalized.col0.s00 != s0.s00, 'finalize changes');
}

#[test]
fn test_finalization_deterministic() {
    let (s0, s1, s2, s3) = get_aes_hash_initial_state();
    let state1 = AesHash1RState { col0: s0, col1: s1, col2: s2, col3: s3 };
    
    let (s0_2, s1_2, s2_2, s3_2) = get_aes_hash_initial_state();
    let state2 = AesHash1RState { col0: s0_2, col1: s1_2, col2: s2_2, col3: s3_2 };
    
    let result1 = aes_hash_finalize(state1);
    let result2 = aes_hash_finalize(state2);
    
    assert(result1.col0.s00 == result2.col0.s00, 'finalize determ');
}

// ============================================================
// State to Bytes Tests
// ============================================================

#[test]
fn test_state_to_bytes_length() {
    let (s0, s1, s2, s3) = get_aes_hash_initial_state();
    let state = AesHash1RState { col0: s0, col1: s1, col2: s2, col3: s3 };
    
    let bytes = aes_hash_state_to_bytes(state);
    
    assert(bytes.len() == 64, '64 bytes');
}

#[test]
fn test_state_to_bytes_order() {
    let (s0, s1, s2, s3) = get_aes_hash_initial_state();
    let state = AesHash1RState { col0: s0, col1: s1, col2: s2, col3: s3 };
    
    let bytes = aes_hash_state_to_bytes(state);
    
    // First 16 bytes should be col0
    assert(*bytes.at(0) == s0.s00, 'first byte');
    // Bytes 16-31 should be col1
    assert(*bytes.at(16) == s1.s00, 'col1 start');
    // Bytes 32-47 should be col2
    assert(*bytes.at(32) == s2.s00, 'col2 start');
    // Bytes 48-63 should be col3
    assert(*bytes.at(48) == s3.s00, 'col3 start');
}

// ============================================================
// Edge Case Tests
// ============================================================

#[test]
fn test_empty_input_still_produces_output() {
    // Empty input (0 blocks) - still goes through finalization
    let input: Array<u8> = array![];
    
    let result = aes_hash_1r(input.span());
    
    // Should still produce 64-byte output (finalization of initial state)
    assert(result.len() == 64, 'output for empty');
}

#[test]
fn test_partial_block_ignored() {
    // 100 bytes = 1 full block + 36 bytes partial (ignored)
    let mut input: Array<u8> = ArrayTrait::new();
    let mut i: usize = 0;
    loop {
        if i >= 100 { break; }
        input.append(0x42);
        i += 1;
    }
    
    // Compare with 64-byte input (1 block)
    let mut input_1block: Array<u8> = ArrayTrait::new();
    let mut i: usize = 0;
    loop {
        if i >= 64 { break; }
        input_1block.append(0x42);
        i += 1;
    }
    
    let result_100 = aes_hash_1r(input.span());
    let result_64 = aes_hash_1r(input_1block.span());
    
    // Both should produce same result (partial block ignored)
    assert(*result_100.at(0) == *result_64.at(0), 'partial ignored');
}
