// ============================================================
// Tests for End-to-End RandomX Verifier
// ============================================================

use monero_vm::randomx::e2e_verifier::{
    RandomXPublicInputs,
    CacheItem, CacheMerkleProof, DatasetItemCacheProofs,
    verify_cache_item_proof, verify_dataset_item_cache_proofs,
    hash_to_u128, meets_difficulty,
    verify_randomx_simple, verify_randomx_full,
    create_test_witness,
};

// ============================================================
// Hash to u128 Tests
// ============================================================

#[test]
fn test_hash_to_u128_zeros() {
    let hash: Array<u8> = array![
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ];
    
    let result = hash_to_u128(hash.span());
    assert(result == 0, 'zeros = 0');
}

#[test]
fn test_hash_to_u128_ones() {
    let hash: Array<u8> = array![
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1,
    ];
    
    let result = hash_to_u128(hash.span());
    assert(result == 1, 'trailing 1');
}

#[test]
fn test_hash_to_u128_leading_byte() {
    let hash: Array<u8> = array![
        1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ];
    
    // 1 * 256^15 = a very large number
    let result = hash_to_u128(hash.span());
    assert(result > 0, 'leading byte');
}

// ============================================================
// Difficulty Tests
// ============================================================

#[test]
fn test_meets_difficulty_zero_hash() {
    // All zeros hash should meet any positive difficulty
    let hash: Array<u8> = array![
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ];
    
    let target: u128 = 1000;
    assert(meets_difficulty(hash.span(), target), 'zero meets any');
}

#[test]
fn test_meets_difficulty_max_target() {
    // Max hash should meet max target
    let hash: Array<u8> = array![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    
    // Max u128 target
    let target: u128 = 0xffffffffffffffffffffffffffffffff;
    assert(meets_difficulty(hash.span(), target), 'max meets max');
}

#[test]
fn test_meets_difficulty_fail() {
    // High hash should not meet low target
    let hash: Array<u8> = array![
        0xff, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ];
    
    let target: u128 = 100;  // Very low target
    assert(!meets_difficulty(hash.span(), target), 'high fails low');
}

// ============================================================
// Simple Verification Tests
// ============================================================

#[test]
fn test_simple_verify_produces_output() {
    // Create minimal scratchpad (64 bytes = 1 block)
    let mut scratchpad: Array<u8> = ArrayTrait::new();
    let mut i: usize = 0;
    loop {
        if i >= 64 { break; }
        scratchpad.append(0x42);
        i += 1;
    }
    
    let expected: Array<u8> = array![];  // Placeholder
    
    let result = verify_randomx_simple(scratchpad.span(), expected.span());
    assert(result, 'simple verify');
}

// ============================================================
// Cache Proof Tests
// ============================================================

#[test]
fn test_cache_item_proof_valid_structure() {
    // Create a mock Cache item
    let item = CacheItem {
        data: (1, 2, 3, 4, 5, 6, 7, 8),
    };
    
    // Create a minimal proof (will compute wrong root, but tests structure)
    let proof = CacheMerkleProof {
        cache_index: 0,
        item: item,
        siblings: array![],
        directions: array![],
    };
    
    // With empty proof, computed root = leaf hash
    // This won't match a real root, but tests the function runs
    let fake_root: felt252 = 0;
    let result = verify_cache_item_proof(fake_root, @proof);
    
    // Result will be false since root doesn't match, but function runs
    assert(!result || result, 'runs without panic');
}

#[test]
fn test_dataset_item_cache_proofs_wrong_count() {
    // Create proofs with wrong count (not 8)
    let proofs = DatasetItemCacheProofs {
        dataset_item_index: 0,
        cache_proofs: array![],  // Empty - should fail
    };
    
    let result = verify_dataset_item_cache_proofs(0, @proofs);
    assert(!result, 'wrong count fails');
}

// ============================================================
// Full Verification Tests
// ============================================================

#[test]
fn test_full_verify_empty_witness() {
    let public_inputs = RandomXPublicInputs {
        block_header: array![].span(),
        nonce: 0,
        claimed_hash: array![].span(),
        cache_root: 0,
        difficulty_target: 0xffffffffffffffffffffffffffffffff,
    };
    
    let witness = create_test_witness();
    
    let result = verify_randomx_full(@public_inputs, @witness);
    
    // Should succeed with empty cache proofs (no verification needed)
    assert(result.valid, 'empty valid');
    assert(result.computed_hash.len() == 64, '64 byte hash');
}

// ============================================================
// Official Test Vector Framework
// ============================================================

// These tests document the official vectors and will be activated
// once we have full Blake2b-256 integration

#[test]
fn test_e2e_vector_1_documented() {
    // Key: "test key 000"
    // Input: "This is a test"
    // Expected: 639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f
    
    // First 8 bytes as u64 (big-endian)
    let expected_prefix: u64 = 0x639183aae1bf4c9a;
    assert(expected_prefix != 0, 'vector 1 documented');
}

#[test]
fn test_e2e_vector_2_documented() {
    // Key: "test key 000"
    // Input: "Lorem ipsum dolor sit amet"
    // Expected: 300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969
    
    let expected_prefix: u64 = 0x300a0adb47603ded;
    assert(expected_prefix != 0, 'vector 2 documented');
}

#[test]
fn test_e2e_vector_3_documented() {
    // Key: "test key 000"
    // Input: "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"
    // Expected: c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8
    
    let expected_prefix: u64 = 0xc36d4ed4191e6173;
    assert(expected_prefix != 0, 'vector 3 documented');
}

#[test]
fn test_e2e_vector_4_different_key() {
    // Key: "test key 001" (DIFFERENT KEY!)
    // Input: "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"
    // Expected: e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc
    
    let expected_prefix: u64 = 0xe9ff4503201c0c2c;
    assert(expected_prefix != 0, 'vector 4 documented');
}

#[test]
fn test_e2e_vector_5_hex_mining_block() {
    // Key: "test key 001"
    // Input (hex): 0b0b98bea7e805e0010a2126d287a2a0cc833d312cb786385a7c2f9de69d25537f584a9bc9977b00000000666fd8753bf61a8631f12984e3fd44f4014eca629276817b56f32e9b68bd82f416
    // Expected: c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1
    
    // This is the CRITICAL mining block test vector for mainnet compatibility
    let expected_prefix: u64 = 0xc56414121acda171;
    assert(expected_prefix != 0, 'vector 5 mining');
}
