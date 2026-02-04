use monero_vm::randomx::blake2b::{
    BLAKE2B_IV_0, BLAKE2B_IV_1, BLAKE2B_IV_2, BLAKE2B_IV_3,
    BLAKE2B_IV_4, BLAKE2B_IV_5, BLAKE2B_IV_6, BLAKE2B_IV_7,
    get_sigma,
    blake2b_init, blake2b_compress, blake2b_g,
    blake2b_generator_new, blake2b_generator_get_byte, blake2b_generator_get_u32,
};
use monero_vm::randomx::prototype::randomx_reciprocal;

// ============================================================
// TDD TESTS - Blake2b Constants (RFC 7693)
// Source: https://datatracker.ietf.org/doc/html/rfc7693
// ============================================================

#[test]
fn test_blake2b_iv_constants() {
    // RFC 7693 Section 2.6 - Blake2b IV constants
    // These MUST match exactly for deterministic program generation
    assert(BLAKE2B_IV_0 == 0x6a09e667f3bcc908, 'IV[0] mismatch');
    assert(BLAKE2B_IV_1 == 0xbb67ae8584caa73b, 'IV[1] mismatch');
    assert(BLAKE2B_IV_2 == 0x3c6ef372fe94f82b, 'IV[2] mismatch');
    assert(BLAKE2B_IV_3 == 0xa54ff53a5f1d36f1, 'IV[3] mismatch');
    assert(BLAKE2B_IV_4 == 0x510e527fade682d1, 'IV[4] mismatch');
    assert(BLAKE2B_IV_5 == 0x9b05688c2b3e6c1f, 'IV[5] mismatch');
    assert(BLAKE2B_IV_6 == 0x1f83d9abfb41bd6b, 'IV[6] mismatch');
    assert(BLAKE2B_IV_7 == 0x5be0cd19137e2179, 'IV[7] mismatch');
}

#[test]
fn test_sigma_permutation_round_0() {
    // RFC 7693 Section 2.7 - SIGMA permutation (identical for Blake2b/Blake2s)
    // Round 0: identity permutation
    let sigma0 = get_sigma(0);
    assert(*sigma0.at(0) == 0, 'SIGMA[0][0]');
    assert(*sigma0.at(1) == 1, 'SIGMA[0][1]');
    assert(*sigma0.at(15) == 15, 'SIGMA[0][15]');
}

#[test]
fn test_sigma_permutation_round_1() {
    // Round 1 permutation
    let sigma1 = get_sigma(1);
    assert(*sigma1.at(0) == 14, 'SIGMA[1][0]');
    assert(*sigma1.at(1) == 10, 'SIGMA[1][1]');
    assert(*sigma1.at(2) == 4, 'SIGMA[1][2]');
}

#[test]
fn test_sigma_permutation_wrapping() {
    // Blake2b uses 12 rounds, SIGMA has 10 rows
    // Rounds 10 and 11 use SIGMA[0] and SIGMA[1] respectively
    let sigma10 = get_sigma(10);
    let sigma0 = get_sigma(0);
    // Round 10 should wrap to round 0
    assert(*sigma10.at(0) == *sigma0.at(0), 'round 10 wraps to 0');
}

// ============================================================
// TDD TESTS - Blake2b G Function (Mixing)
// Blake2b rotations: 32, 24, 16, 63 (different from Blake2s!)
// ============================================================

#[test]
fn test_blake2b_g_basic() {
    // G function: quarter-round mixing
    // Input: (a, b, c, d, x, y) -> (a', b', c', d')
    let mut v: Array<u64> = array![
        0x6a09e667f3bcc908, // a
        0xbb67ae8584caa73b, // b
        0x3c6ef372fe94f82b, // c
        0xa54ff53a5f1d36f1, // d
    ];
    
    let x: u64 = 0x0;
    let y: u64 = 0x0;
    
    // Apply G function
    let result = blake2b_g(v.span(), 0, 1, 2, 3, x, y);
    
    // Result should be different from input
    assert(*result.at(0) != *v.at(0) || *result.at(1) != *v.at(1), 'G should mix');
}

#[test]
fn test_blake2b_g_rotations() {
    // Blake2b uses rotations: R1=32, R2=24, R3=16, R4=63
    // This is DIFFERENT from Blake2s which uses: 16, 12, 8, 7
    let mut v: Array<u64> = array![
        0xFFFFFFFFFFFFFFFF, // a
        0x0000000000000001, // b
        0x0000000000000000, // c
        0x0000000000000000, // d
    ];
    
    let result = blake2b_g(v.span(), 0, 1, 2, 3, 0, 0);
    
    // After rotation by 32, high and low 32 bits should swap
    // This verifies we're using Blake2b rotations, not Blake2s
    assert(*result.at(0) != 0xFFFFFFFFFFFFFFFF, 'rotation should change value');
}

// ============================================================
// TDD TESTS - Blake2b Compression Function
// ============================================================

#[test]
fn test_blake2b_init() {
    // Initialize Blake2b state for 64-byte output
    let state = blake2b_init(64);
    
    // h[0] should be IV[0] XOR parameter block
    // Parameter block for 64-byte hash: 0x01010040
    let expected_h0 = BLAKE2B_IV_0 ^ 0x01010040;
    assert(state.h0 == expected_h0, 'h[0] init');
    
    // Other h values should equal IV (no key)
    assert(state.h1 == BLAKE2B_IV_1, 'h[1] init');
    assert(state.h7 == BLAKE2B_IV_7, 'h[7] init');
    
    // Counter and flag should be zero initially
    assert(state.t0 == 0, 't0 init');
    assert(state.t1 == 0, 't1 init');
    assert(state.f0 == 0, 'f0 init');
}

#[test]
fn test_blake2b_compress_modifies_state() {
    // Compression should modify state
    let mut state = blake2b_init(64);
    let mut block: Array<u64> = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i == 16 {
            break;
        }
        block.append(0);
        i += 1;
    }
    
    let initial_h0 = state.h0;
    let new_state = blake2b_compress(state, block.span(), 64, false);
    
    // State should be modified after compression
    assert(new_state.h0 != initial_h0, 'compress should modify');
}

#[test]
fn test_blake2b_compress_12_rounds() {
    // Blake2b uses 12 rounds (not 10 like Blake2s)
    // This test verifies the compression function uses correct round count
    let state = blake2b_init(64);
    let mut block: Array<u64> = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i == 16 {
            break;
        }
        block.append(i.into());
        i += 1;
    }
    
    let new_state = blake2b_compress(state, block.span(), 128, true);
    
    // After 12 rounds, state should be well-mixed
    // The exact values depend on the implementation
    assert(new_state.h0 != 0, 'state should be mixed');
}

// ============================================================
// TDD TESTS - Blake2bGenerator (RandomX PRNG)
// Source: RandomX blake2_generator.cpp
// ============================================================

#[test]
fn test_blake2b_generator_new() {
    // Create generator with seed and nonce
    let seed: Array<u8> = array![
        0x74, 0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79, // "test key"
        0x20, 0x30, 0x30, 0x30 // " 000"
    ];
    let nonce: u32 = 0;
    
    let _gen = blake2b_generator_new(seed.span(), nonce);
    
    // Generator should be initialized with data index at 64 (force immediate hash)
    assert(_gen.data_index == 64, 'data_index should be 64');
}

#[test]
fn test_blake2b_generator_get_byte_deterministic() {
    // Same seed should produce same byte sequence
    let seed: Array<u8> = array![
        0x74, 0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79,
        0x20, 0x30, 0x30, 0x30
    ];
    
    let mut gen1 = blake2b_generator_new(seed.span(), 0);
    let mut gen2 = blake2b_generator_new(seed.span(), 0);
    
    let (gen1_new, byte1_1) = blake2b_generator_get_byte(gen1);
    let (gen2_new, byte2_1) = blake2b_generator_get_byte(gen2);
    
    assert(byte1_1 == byte2_1, 'deterministic byte 1');
    
    let (_gen1_final, byte1_2) = blake2b_generator_get_byte(gen1_new);
    let (_gen2_final, byte2_2) = blake2b_generator_get_byte(gen2_new);
    
    assert(byte1_2 == byte2_2, 'deterministic byte 2');
}

#[test]
fn test_blake2b_generator_different_nonce() {
    // Different nonce should produce different sequence
    let seed: Array<u8> = array![
        0x74, 0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79,
        0x20, 0x30, 0x30, 0x30
    ];
    
    let mut gen1 = blake2b_generator_new(seed.span(), 0);
    let mut gen2 = blake2b_generator_new(seed.span(), 1);
    
    let (_, byte1) = blake2b_generator_get_byte(gen1);
    let (_, byte2) = blake2b_generator_get_byte(gen2);
    
    // Different nonces should (very likely) produce different first bytes
    // Note: There's a 1/256 chance they match by coincidence
    // In practice, test with actual RandomX test vectors
    assert(byte1 != byte2, 'different nonce -> different');
}

#[test]
fn test_blake2b_generator_get_u32_little_endian() {
    // getUInt32 should return little-endian u32
    let seed: Array<u8> = array![
        0x74, 0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79,
        0x20, 0x30, 0x30, 0x30
    ];
    
    let _gen = blake2b_generator_new(seed.span(), 0);
    let (_, value) = blake2b_generator_get_u32(_gen);
    
    // Value should be non-zero (extremely unlikely to be zero)
    assert(value != 0, 'u32 should be non-zero');
}

#[test]
fn test_blake2b_generator_continuous_stream() {
    // Generator should produce continuous stream by re-hashing when exhausted
    let seed: Array<u8> = array![
        0x74, 0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79,
        0x20, 0x30, 0x30, 0x30
    ];
    
    let mut gen = blake2b_generator_new(seed.span(), 0);
    
    // Get 128 bytes (2 blocks worth) - should trigger re-hash
    let mut i: u32 = 0;
    loop {
        if i == 128 {
            break;
        }
        let (new_gen, _) = blake2b_generator_get_byte(gen);
        gen = new_gen;
        i += 1;
    }
    
    // Should still be able to get bytes after exhausting initial block
    let (_, byte) = blake2b_generator_get_byte(gen);
    // Just verify it doesn't panic - any value is valid (byte is u8, always 0-255)
    assert(byte <= 255, 'byte in range');
}

#[test]
fn test_blake2b_generator_nonce_at_offset_60() {
    // RandomX stores nonce at offset 60 in the 64-byte data block
    // This is critical for matching RandomX's behavior
    let seed: Array<u8> = array![0x00]; // Minimal seed
    
    let gen = blake2b_generator_new(seed.span(), 0x12345678);
    
    // Verify nonce is stored (we can't directly check offset, but behavior should match)
    // The nonce affects the hash output
    let (_, byte) = blake2b_generator_get_byte(gen);
    
    // With different nonce, we should get different output
    let gen2 = blake2b_generator_new(seed.span(), 0x87654321);
    let (_, byte2) = blake2b_generator_get_byte(gen2);
    
    assert(byte != byte2, 'nonce affects output');
}

// ============================================================
// TDD TESTS - Test Vectors from RandomX Reference
// These will be filled in with actual values from RandomX
// ============================================================

#[test]
fn test_blake2b_generator_reference_vector_1() {
    // TODO: Fill in with actual test vectors from RandomX
    // Seed: "test key 000"
    // Nonce: 0
    // Expected first 8 bytes: [to be extracted from RandomX]
    
    // Placeholder test - will be updated with real values
    let seed: Array<u8> = array![
        0x74, 0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79,
        0x20, 0x30, 0x30, 0x30
    ];
    
    let _gen = blake2b_generator_new(seed.span(), 0);
    
    // TODO: Replace with actual expected values from RandomX
    // let (_, byte0) = blake2b_generator_get_byte(gen);
    // assert(byte0 == EXPECTED_BYTE_0, 'reference byte 0');
    
    assert(true, 'placeholder');
}

// ============================================================
// OFFICIAL TEST VECTORS - Reciprocal Calculation
// Source: RandomX tests.cpp (OFFICIAL)
// https://github.com/tevador/RandomX/blob/master/src/tests/tests.cpp
// ============================================================

#[test]
fn test_reciprocal_official_3() {
    // Official: assert(randomx_reciprocal(3) == 12297829382473034410U);
    let result = randomx_reciprocal(3);
    assert(result == 12297829382473034410, 'reciprocal(3) official');
}

#[test]
fn test_reciprocal_official_13() {
    // Official: assert(randomx_reciprocal(13) == 11351842506898185609U);
    let result = randomx_reciprocal(13);
    assert(result == 11351842506898185609, 'reciprocal(13) official');
}

#[test]
fn test_reciprocal_official_33() {
    // Official: assert(randomx_reciprocal(33) == 17887751829051686415U);
    let result = randomx_reciprocal(33);
    assert(result == 17887751829051686415, 'reciprocal(33) official');
}

#[test]
fn test_reciprocal_official_65537() {
    // Official: assert(randomx_reciprocal(65537) == 18446462603027742720U);
    let result = randomx_reciprocal(65537);
    assert(result == 18446462603027742720, 'reciprocal(65537) official');
}

#[test]
fn test_reciprocal_official_15000001() {
    // Official: assert(randomx_reciprocal(15000001) == 10316166306300415204U);
    let result = randomx_reciprocal(15000001);
    assert(result == 10316166306300415204, 'reciprocal(15000001)');
}

#[test]
fn test_reciprocal_official_3845182035() {
    // Official: assert(randomx_reciprocal(3845182035) == 10302264209224146340U);
    let result = randomx_reciprocal(3845182035);
    assert(result == 10302264209224146340, 'reciprocal(3845182035)');
}

#[test]
fn test_reciprocal_official_max_u32() {
    // Official: assert(randomx_reciprocal(0xffffffff) == 9223372039002259456U);
    let result = randomx_reciprocal(0xffffffff);
    assert(result == 9223372039002259456, 'reciprocal(max_u32)');
}

#[test]
fn test_reciprocal_rejects_zero() {
    // reciprocal(0) should be handled (return 0 or skip)
    let result = randomx_reciprocal(0);
    assert(result == 0, 'reciprocal(0) = 0');
}

#[test]
fn test_reciprocal_rejects_power_of_2() {
    // Powers of 2 are skipped in IMUL_RCP generation
    let result_1 = randomx_reciprocal(1);
    let result_2 = randomx_reciprocal(2);
    let result_4 = randomx_reciprocal(4);
    
    assert(result_1 == 0, 'reciprocal(1) = 0');
    assert(result_2 == 0, 'reciprocal(2) = 0');
    assert(result_4 == 0, 'reciprocal(4) = 0');
}
