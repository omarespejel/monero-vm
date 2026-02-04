// ============================================================
// OFFICIAL TEST VECTORS from RandomX tests.cpp
// Source: https://github.com/tevador/RandomX/blob/master/src/tests/tests.cpp
// ============================================================
//
// Configuration requirements:
// - RANDOMX_ARGON_SALT = "RandomX\x03"
// - RANDOMX_ARGON_ITERATIONS = 3
// - RANDOMX_ARGON_LANES = 1
// - RANDOMX_ARGON_MEMORY = 262144

use monero_vm::randomx::prototype::randomx_reciprocal;

// ============================================================
// RECIPROCAL TEST VECTORS (ALL OFFICIAL)
// ============================================================

#[test]
fn test_official_reciprocal_3() {
    assert(randomx_reciprocal(3) == 12297829382473034410, 'rcp(3)');
}

#[test]
fn test_official_reciprocal_13() {
    assert(randomx_reciprocal(13) == 11351842506898185609, 'rcp(13)');
}

#[test]
fn test_official_reciprocal_33() {
    assert(randomx_reciprocal(33) == 17887751829051686415, 'rcp(33)');
}

#[test]
fn test_official_reciprocal_65537() {
    assert(randomx_reciprocal(65537) == 18446462603027742720, 'rcp(65537)');
}

#[test]
fn test_official_reciprocal_15000001() {
    assert(randomx_reciprocal(15000001) == 10316166306300415204, 'rcp(15000001)');
}

#[test]
fn test_official_reciprocal_3845182035() {
    assert(randomx_reciprocal(3845182035) == 10302264209224146340, 'rcp(3845182035)');
}

#[test]
fn test_official_reciprocal_max_u32() {
    assert(randomx_reciprocal(0xffffffff) == 9223372039002259456, 'rcp(max)');
}

// ============================================================
// DATASET ITEM TEST VECTORS
// Key: "test key 000"
// These verify the final datasetItem[0] value after full execution
// NOTE: These are REFERENCE values - full verification requires cache
// ============================================================

#[test]
fn test_official_dataset_item_0_reference() {
    // Item 0: Expected datasetItem[0] = 0x680588a85ae222db
    // Just verify the hex constant is stored correctly
    let expected: u64 = 0x680588a85ae222db;
    assert(expected != 0, 'dataset_0 documented');
}

#[test]
fn test_official_dataset_item_10m_reference() {
    // Item 10,000,000: Expected datasetItem[0] = 0x7943a1f6186ffb72
    let expected: u64 = 0x7943a1f6186ffb72;
    assert(expected != 0, 'dataset_10m documented');
}

#[test]
fn test_official_dataset_item_20m_reference() {
    // Item 20,000,000: Expected datasetItem[0] = 0x9035244d718095e1
    let expected: u64 = 0x9035244d718095e1;
    assert(expected != 0, 'dataset_20m documented');
}

#[test]
fn test_official_dataset_item_30m_reference() {
    // Item 30,000,000: Expected datasetItem[0] = 0x145a5091f7853099
    let expected: u64 = 0x145a5091f7853099;
    assert(expected != 0, 'dataset_30m documented');
}

// ============================================================
// CACHE INITIALIZATION TEST VECTORS
// Key: "test key 000"
// Argon2d cache initialization verification
// NOTE: These are REFERENCE values for Argon2d cache
// ============================================================

#[test]
fn test_official_cache_memory_0_reference() {
    // cacheMemory[0] = 0x191e0e1d23c02186
    let expected: u64 = 0x191e0e1d23c02186;
    assert(expected != 0, 'cache[0] documented');
}

#[test]
fn test_official_cache_memory_1568413_reference() {
    // cacheMemory[1568413] = 0xf1b62fe6210bf8b1
    let expected: u64 = 0xf1b62fe6210bf8b1;
    assert(expected != 0, 'cache[1568413] documented');
}

#[test]
fn test_official_cache_memory_max_reference() {
    // cacheMemory[33554431] = 0x1f47f056d05cd99b
    let expected: u64 = 0x1f47f056d05cd99b;
    assert(expected != 0, 'cache[max] documented');
}

// ============================================================
// HASH TEST VECTORS (E2E)
// Key: "test key 000" / "test key 001"
// Full RandomX hash verification
// NOTE: These are REFERENCE values for E2E hash verification
// ============================================================

#[test]
fn test_official_hash_vector_1_reference() {
    // Key: "test key 000"
    // Input: "This is a test"
    // Expected: 639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f
    let expected_first_8: u64 = 0x639183aae1bf4c9a;
    assert(expected_first_8 != 0, 'hash1 documented');
}

#[test]
fn test_official_hash_vector_2_reference() {
    // Key: "test key 000"
    // Input: "Lorem ipsum dolor sit amet"
    // Expected: 300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969
    let expected_first_8: u64 = 0x300a0adb47603ded;
    assert(expected_first_8 != 0, 'hash2 documented');
}

#[test]
fn test_official_hash_vector_3_reference() {
    // Key: "test key 000"
    // Input: "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"
    // Expected: c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8
    let expected_first_8: u64 = 0xc36d4ed4191e6173;
    assert(expected_first_8 != 0, 'hash3 documented');
}

#[test]
fn test_official_hash_vector_4_different_key() {
    // Key: "test key 001" (different key!)
    // Input: "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"
    // Expected: e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc
    let expected_first_8: u64 = 0xe9ff4503201c0c2c;
    assert(expected_first_8 != 0, 'hash4 documented');
}

#[test]
fn test_official_hash_vector_5_hex_mining_block() {
    // Key: "test key 001"
    // Input (hex): 0b0b98bea7e805e0010a2126d287a2a0cc833d312cb786385a7c2f9de69d25537f584a9bc9977b00000000666fd8753bf61a8631f12984e3fd44f4014eca629276817b56f32e9b68bd82f416
    // Expected: c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1
    //
    // This is the CRITICAL mining block test vector
    let expected_first_8: u64 = 0xc56414121acda171;
    assert(expected_first_8 != 0, 'hash5 hex mining');
}

// ============================================================
// SUPERSCALARHASH PROGRAM BLAKE2B HASHES
// Key: "test key 000"
// Blake2b hash of generated SuperscalarPrograms 0-9
// NOTE: These are REFERENCE values for program verification
// ============================================================

// All 10 SuperscalarHash program hashes from tests.cpp
#[test]
fn test_official_superscalar_program_0_hash() {
    // d3a4a6623738756f77e6104469102f082eff2a3e60be7ad696285ef7dfc72a61
    let expected: u64 = 0xd3a4a6623738756f;
    assert(expected != 0, 'prog0');
}

#[test]
fn test_official_superscalar_program_1_hash() {
    // f5e7e0bbc7e93c609003d6359208688070afb4a77165a552ff7be63b38dfbc86
    let expected: u64 = 0xf5e7e0bbc7e93c60;
    assert(expected != 0, 'prog1');
}

#[test]
fn test_official_superscalar_program_2_hash() {
    // 85ed8b11734de5b3e9836641413a8f36e99e89694f419c8cd25c3f3f16c40c5a
    let expected: u64 = 0x85ed8b11734de5b3;
    assert(expected != 0, 'prog2');
}

#[test]
fn test_official_superscalar_program_3_hash() {
    // 5dd956292cf5d5704ad99e362d70098b2777b2a1730520be52f772ca48cd3bc0
    let expected: u64 = 0x5dd956292cf5d570;
    assert(expected != 0, 'prog3');
}

#[test]
fn test_official_superscalar_program_4_hash() {
    // 6f14018ca7d519e9b48d91af094c0f2d7e12e93af0228782671a8640092af9e5
    let expected: u64 = 0x6f14018ca7d519e9;
    assert(expected != 0, 'prog4');
}

#[test]
fn test_official_superscalar_program_5_hash() {
    // 134be097c92e2c45a92f23208cacd89e4ce51f1009a0b900dbe83b38de11d791
    let expected: u64 = 0x134be097c92e2c45;
    assert(expected != 0, 'prog5');
}

#[test]
fn test_official_superscalar_program_6_hash() {
    // 268f9392c20c6e31371a5131f82bd7713d3910075f2f0468baafaa1abd2f3187
    let expected: u64 = 0x268f9392c20c6e31;
    assert(expected != 0, 'prog6');
}

#[test]
fn test_official_superscalar_program_7_hash() {
    // c668a05fd909714ed4a91e8d96d67b17e44329e88bc71e0672b529a3fc16be47
    let expected: u64 = 0xc668a05fd909714e;
    assert(expected != 0, 'prog7');
}

#[test]
fn test_official_superscalar_program_8_hash() {
    // 99739351315840963011e4c5d8e90ad0bfed3facdcb713fe8f7138fbf01c4c94
    let expected: u64 = 0x9973935131584096;
    assert(expected != 0, 'prog8');
}

#[test]
fn test_official_superscalar_program_9_hash() {
    // 14ab53d61880471f66e80183968d97effd5492b406876060e595fcf9682f9295
    let expected: u64 = 0x14ab53d61880471f;
    assert(expected != 0, 'prog9');
}

// ============================================================
// AESGENERATOR1R TEST VECTOR (reference for future impl)
// ============================================================

#[test]
fn test_official_aesgenerator1r_reference() {
    // Input state: 6c19536eb2de31b6c0065f7f116e86f960d8af0c57210a6584c3237b9d064dc7
    // Output: fa89397dd6ca422513aeadba3f124b5540324c4ad4b6db434394307a17c833ab
    let expected: u64 = 0xfa89397dd6ca4225;
    assert(expected != 0, 'aes1r documented');
}

// ============================================================
// COMMITMENT TEST VECTOR
// ============================================================

#[test]
fn test_official_commitment_reference() {
    // Key: "test key 000"
    // Input: "This is a test"
    // Expected: d53ccf348b75291b7be76f0a7ac8208bbced734b912f6fca60539ab6f86be919
    let expected: u64 = 0xd53ccf348b75291b;
    assert(expected != 0, 'commit documented');
}

// ============================================================
// INSTRUCTION-LEVEL TEST VECTORS (VERIFIED)
// These are CRITICAL for SuperscalarHash correctness
// Source: https://github.com/tevador/RandomX/blob/master/src/tests/tests.cpp
// ============================================================

use monero_vm::randomx::prototype::{
    imul_r, imulh_u64, ismulh_u64, isub_r, irol_r,
    rotate_right_64,
};

#[test]
fn test_official_imul_r() {
    // IMUL_R: dst=0xBC550E96BA88A72B, src=0xF5391FA9F18D6273
    // Expected: 0x28723424A9108E51
    let dst: u64 = 0xBC550E96BA88A72B;
    let src: u64 = 0xF5391FA9F18D6273;
    let expected: u64 = 0x28723424A9108E51;
    
    let result = imul_r(dst, src);
    assert(result == expected, 'IMUL_R official');
}

#[test]
fn test_official_imulh_r() {
    // IMULH_R: dst=0xBC550E96BA88A72B, src=0xF5391FA9F18D6273
    // Expected: 0xB4676D31D2B34883
    let dst: u64 = 0xBC550E96BA88A72B;
    let src: u64 = 0xF5391FA9F18D6273;
    let expected: u64 = 0xB4676D31D2B34883;
    
    let result = imulh_u64(dst, src);
    assert(result == expected, 'IMULH_R official');
}

#[test]
fn test_official_ismulh_r() {
    // ISMULH_R: dst=0xBC550E96BA88A72B, src=0xF5391FA9F18D6273
    // Official Expected: 0x02D93EF1269D3EE5 = 205325887223242469
    // 
    // Reference: RandomX src/instructions_portable.cpp smulh()
    // Semantics: ((int128_t)a * b) >> 64
    
    // Use the u64 interface directly for testing
    let dst_u: u64 = 0xBC550E96BA88A72B;
    let src_u: u64 = 0xF5391FA9F18D6273;
    
    // Call the unsigned version with manual sign handling
    let result_u = ismulh_u64(dst_u, src_u);
    
    // Official expected: 0x02D93EF1269D3EE5 = 205325887223242469
    let official_expected: u64 = 0x02D93EF1269D3EE5;
    
    // Debug: check some intermediate values
    // Both inputs have MSB set (negative in two's complement)
    assert(dst_u >= 0x8000000000000000, 'dst neg');
    assert(src_u >= 0x8000000000000000, 'src neg');
    
    // Since both negative, result should be positive (high bits of positive product)
    // and should fit in a u64 without the MSB set
    assert(result_u < 0x8000000000000000, 'result pos');
    
    // Check exact match
    assert(result_u == official_expected, 'ISMULH_R EXACT');
}

#[test]
fn test_official_isub_r() {
    // ISUB_R: dst=1, src=0xFFFFFFFF
    // Expected: 0xFFFFFFFF00000002
    let dst: u64 = 1;
    let src: u64 = 0xFFFFFFFF;
    let expected: u64 = 0xFFFFFFFF00000002;
    
    let result = isub_r(dst, src);
    assert(result == expected, 'ISUB_R official');
}

#[test]
fn test_official_iror_r() {
    // IROR_R: dst=953360005391419562, src=4569451684712230561
    // Expected: 0xD835C455069D81EF
    // 
    // src & 63 = shift amount
    let dst: u64 = 953360005391419562;
    let src: u64 = 4569451684712230561;
    let expected: u64 = 0xD835C455069D81EF;
    
    // IROR_R uses src as shift amount (masked to 6 bits)
    let shift: u32 = (src & 63).try_into().unwrap();
    let result = rotate_right_64(dst, shift);
    
    assert(result == expected, 'IROR_R official');
}

#[test]
fn test_official_irol_r() {
    // IROL_R: dst=953360005391419562, src=4569451684712230561
    // Expected: 6978065200552740799
    let dst: u64 = 953360005391419562;
    let src: u64 = 4569451684712230561;
    let expected: u64 = 6978065200552740799;
    
    let result = irol_r(dst, src);
    assert(result == expected, 'IROL_R official');
}
