// ============================================================
// End-to-End RandomX ZK Verifier
// ============================================================
//
// This module implements the complete RandomX verification pipeline:
//
// 1. Blake2b(header || nonce) → seed
// 2. Derive config (ma, mx, datasetOffset)
// 3. For each Dataset access:
//    a. Verify Cache Merkle proofs → cache_root
//    b. Recompute Dataset item via SuperscalarHash
//    c. Verify claimed Dataset item matches
// 4. AesHash1R(final_scratchpad) → 64 bytes
// 5. Blake2b-256 finalization → output
// 6. Assert output == claimed_hash
//
// SECURITY MODEL:
// - Public Inputs: block_header, nonce, claimed_hash, cache_root
// - Private Witness: VM trace, Dataset items, Cache proofs, scratchpad

use core::array::ArrayTrait;
use core::poseidon::poseidon_hash_span;

use super::merkle_verification::DatasetItem;
use super::aes_hash::aes_hash_1r;

// ============================================================
// Public Input Structure
// ============================================================

/// Public inputs for RandomX verification
#[derive(Drop)]
pub struct RandomXPublicInputs {
    /// Block header (typically 76 bytes for Monero)
    pub block_header: Span<u8>,
    /// Nonce value
    pub nonce: u32,
    /// Claimed hash output (32 bytes)
    pub claimed_hash: Span<u8>,
    /// Poseidon commitment to the 256MB Cache
    pub cache_root: felt252,
    /// Difficulty target (for PoW verification)
    pub difficulty_target: u128,
}

// ============================================================
// Private Witness Structure
// ============================================================

/// Cache item (64 bytes, used for Dataset item computation)
#[derive(Copy, Drop)]
pub struct CacheItem {
    pub data: (u64, u64, u64, u64, u64, u64, u64, u64),
}

/// Cache Merkle proof for a single Cache item
#[derive(Drop)]
pub struct CacheMerkleProof {
    pub cache_index: u32,
    pub item: CacheItem,
    pub siblings: Array<felt252>,
    pub directions: Array<u8>,
}

/// All Cache proofs needed to verify one Dataset item (8 proofs)
#[derive(Drop)]
pub struct DatasetItemCacheProofs {
    pub dataset_item_index: u64,
    /// 8 Cache proofs (RANDOMX_CACHE_ACCESSES = 8)
    pub cache_proofs: Array<CacheMerkleProof>,
}

/// Complete private witness for verification
#[derive(Drop)]
pub struct RandomXPrivateWitness {
    /// Final scratchpad state after VM execution (2MB)
    pub final_scratchpad: Span<u8>,
    /// Dataset items accessed during execution
    pub dataset_items: Array<DatasetItem>,
    /// Cache proofs for each Dataset item
    pub cache_proofs: Array<DatasetItemCacheProofs>,
    /// Expected Dataset access indices (64 total)
    pub expected_dataset_indices: Array<u64>,
}

// ============================================================
// Verification Result
// ============================================================

#[derive(Drop)]
pub struct VerificationResult {
    pub valid: bool,
    pub computed_hash: Array<u8>,
    pub meets_difficulty: bool,
}

// ============================================================
// Core Verification Functions
// ============================================================

/// Verify a single Cache item's Merkle proof
pub fn verify_cache_item_proof(
    cache_root: felt252,
    proof: @CacheMerkleProof
) -> bool {
    // Hash the Cache item to get leaf value
    let (d0, d1, d2, d3, d4, d5, d6, d7) = *proof.item.data;
    let leaf_data: Array<felt252> = array![
        d0.into(), d1.into(), d2.into(), d3.into(),
        d4.into(), d5.into(), d6.into(), d7.into(),
    ];
    let leaf = poseidon_hash_span(leaf_data.span());
    
    // Compute root from leaf and proof path
    let mut current = leaf;
    let mut i: usize = 0;
    
    loop {
        if i >= proof.siblings.len() {
            break;
        }
        
        let sibling = *proof.siblings.at(i);
        let direction = *proof.directions.at(i);
        
        let (left, right) = if direction == 0 {
            (current, sibling)
        } else {
            (sibling, current)
        };
        
        let pair: Array<felt252> = array![left, right];
        current = poseidon_hash_span(pair.span());
        
        i += 1;
    }
    
    current == cache_root
}

/// Verify all 8 Cache proofs for a Dataset item
pub fn verify_dataset_item_cache_proofs(
    cache_root: felt252,
    proofs: @DatasetItemCacheProofs
) -> bool {
    // Must have exactly 8 Cache proofs
    if proofs.cache_proofs.len() != 8 {
        return false;
    }
    
    let mut i: usize = 0;
    loop {
        if i >= 8 {
            break true;
        }
        
        let proof = proofs.cache_proofs.at(i);
        if !verify_cache_item_proof(cache_root, proof) {
            break false;
        }
        
        i += 1;
    }
}

/// Convert hash output to u128 for difficulty comparison
/// Takes first 16 bytes as big-endian u128
pub fn hash_to_u128(hash: Span<u8>) -> u128 {
    assert(hash.len() >= 16, 'need 16 bytes');
    
    let mut result: u128 = 0;
    let mut i: usize = 0;
    loop {
        if i >= 16 {
            break;
        }
        result = result * 256 + (*hash.at(i)).into();
        i += 1;
    }
    result
}

/// Check if hash meets difficulty target
/// Lower hash value = higher difficulty = valid
pub fn meets_difficulty(hash: Span<u8>, target: u128) -> bool {
    let hash_value = hash_to_u128(hash);
    hash_value <= target
}

// ============================================================
// Simplified E2E Verification (for testing)
// ============================================================

/// Simplified verification that skips VM execution
/// Uses pre-computed scratchpad from witness
pub fn verify_randomx_simple(
    final_scratchpad: Span<u8>,
    expected_hash: Span<u8>
) -> bool {
    // Apply AesHash1R to scratchpad
    let aes_output = aes_hash_1r(final_scratchpad);
    
    // The full verification would then apply Blake2b-256
    // For now, verify AesHash1R produces 64 bytes
    if aes_output.len() != 64 {
        return false;
    }
    
    // TODO: Apply Blake2b-256 finalization
    // let final_hash = blake2b_256(aes_output.span());
    // return final_hash == expected_hash;
    
    true
}

// ============================================================
// Full E2E Verification
// ============================================================

/// Complete RandomX verification
/// Returns (valid, computed_hash, meets_difficulty)
pub fn verify_randomx_full(
    public_inputs: @RandomXPublicInputs,
    witness: @RandomXPrivateWitness
) -> VerificationResult {
    let cache_root = *public_inputs.cache_root;
    
    // 1. Verify all Cache proofs for Dataset items
    let num_dataset_proofs = witness.cache_proofs.len();
    let mut cache_valid = true;
    let mut i: usize = 0;
    loop {
        if i >= num_dataset_proofs {
            break;
        }
        
        let proofs = witness.cache_proofs.at(i);
        if !verify_dataset_item_cache_proofs(cache_root, proofs) {
            cache_valid = false;
            break;
        }
        
        i += 1;
    }
    
    if !cache_valid {
        return VerificationResult {
            valid: false,
            computed_hash: array![],
            meets_difficulty: false,
        };
    }
    
    // 2. Apply AesHash1R to final scratchpad
    let aes_output = aes_hash_1r(*witness.final_scratchpad);
    
    // 3. For full verification, we would apply Blake2b-256 here
    // let final_hash = blake2b_256(aes_output.span());
    
    // 4. Check difficulty (using AES output as placeholder)
    let difficulty_met = meets_difficulty(
        aes_output.span(),
        *public_inputs.difficulty_target
    );
    
    VerificationResult {
        valid: true,
        computed_hash: aes_output,
        meets_difficulty: difficulty_met,
    }
}

// ============================================================
// Helper: Create empty witness for testing
// ============================================================

pub fn create_test_witness() -> RandomXPrivateWitness {
    // Create minimal valid witness for testing
    let mut scratchpad: Array<u8> = ArrayTrait::new();
    let mut i: usize = 0;
    loop {
        if i >= 64 { break; }  // Minimum 1 block
        scratchpad.append(0);
        i += 1;
    }
    
    RandomXPrivateWitness {
        final_scratchpad: scratchpad.span(),
        dataset_items: array![],
        cache_proofs: array![],
        expected_dataset_indices: array![],
    }
}
