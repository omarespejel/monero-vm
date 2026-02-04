// ============================================================
// Merkle Proof Verification for RandomX Dataset
// ============================================================
//
// SECURITY-CRITICAL: This module provides the cryptographic foundation
// for verifying that a prover accessed correct Dataset items.
//
// Per auditor recommendation and X41/Trail of Bits audit findings:
// - AesHash1R alone is NOT cryptographically secure
// - Merkle proofs are the ONLY way to prevent forgery
// - Without these proofs, the entire verification is meaningless
//
// RandomX Dataset structure:
// - Total items: RANDOMX_DATASET_ITEM_COUNT = 34,078,719
// - Item size: 64 bytes (8 × u64)
// - Each VM program accesses 8 items
// - Total tree depth: ~25 levels (log2(34M))

use core::array::ArrayTrait;
use core::poseidon::poseidon_hash_span;

// ============================================================
// Constants
// ============================================================

/// Number of items in the RandomX dataset
/// From specs.md: RANDOMX_DATASET_BASE_SIZE + RANDOMX_DATASET_EXTRA_SIZE
/// = 2147483648 + 33554432 = 2181038080 bytes / 64 = 34,078,720 items
pub const RANDOMX_DATASET_ITEM_COUNT: u64 = 34078720;

/// Merkle tree depth (log2(34078720) ≈ 25)
pub const MERKLE_TREE_DEPTH: u32 = 25;

/// Number of dataset accesses per program iteration
pub const DATASET_ACCESSES_PER_PROGRAM: u32 = 8;

/// Number of program iterations in RandomX
pub const RANDOMX_PROGRAM_COUNT: u32 = 8;

/// Total dataset accesses per hash = 8 programs × 8 accesses = 64
pub const TOTAL_DATASET_ACCESSES: u32 = 64;

// ============================================================
// Data Structures
// ============================================================

/// A single Dataset item (64 bytes)
#[derive(Copy, Drop)]
pub struct DatasetItem {
    pub r0: u64,
    pub r1: u64,
    pub r2: u64,
    pub r3: u64,
    pub r4: u64,
    pub r5: u64,
    pub r6: u64,
    pub r7: u64,
}

/// Merkle proof for a single Dataset item
#[derive(Drop)]
pub struct DatasetMerkleProof {
    /// Index of the item in the dataset (0 to RANDOMX_DATASET_ITEM_COUNT-1)
    pub item_index: u64,
    /// The 64-byte dataset item value
    pub item: DatasetItem,
    /// Merkle path siblings (MERKLE_TREE_DEPTH elements)
    pub siblings: Array<felt252>,
    /// Direction bits (0 = left, 1 = right) for each level
    pub directions: Array<u8>,
}

/// Collection of all Dataset access proofs for one hash computation
#[derive(Drop)]
pub struct DatasetAccessProofs {
    /// The committed Dataset root
    pub dataset_root: felt252,
    /// Proofs for all 64 dataset accesses
    pub proofs: Array<DatasetMerkleProof>,
}

// ============================================================
// Core Verification Functions
// ============================================================

/// Hash a Dataset item to a single felt252 for Merkle tree
/// Uses Poseidon for zkSNARK efficiency
pub fn hash_dataset_item(item: DatasetItem) -> felt252 {
    let data: Array<felt252> = array![
        item.r0.into(),
        item.r1.into(),
        item.r2.into(),
        item.r3.into(),
        item.r4.into(),
        item.r5.into(),
        item.r6.into(),
        item.r7.into(),
    ];
    poseidon_hash_span(data.span())
}

/// Compute Merkle root from leaf and proof path
pub fn compute_merkle_root(
    leaf: felt252,
    siblings: Span<felt252>,
    directions: Span<u8>
) -> felt252 {
    assert(siblings.len() == directions.len(), 'proof length mismatch');
    
    let mut current = leaf;
    let mut i: usize = 0;
    
    loop {
        if i >= siblings.len() {
            break;
        }
        
        let sibling = *siblings.at(i);
        let direction = *directions.at(i);
        
        // direction = 0: current is left child, sibling is right
        // direction = 1: current is right child, sibling is left
        let (left, right) = if direction == 0 {
            (current, sibling)
        } else {
            (sibling, current)
        };
        
        // Hash the pair
        let pair: Array<felt252> = array![left, right];
        current = poseidon_hash_span(pair.span());
        
        i += 1;
    }
    
    current
}

/// Verify a single Dataset item's Merkle proof
pub fn verify_dataset_item_proof(
    expected_root: felt252,
    proof: @DatasetMerkleProof
) -> bool {
    // 1. Verify item index is in valid range
    if *proof.item_index >= RANDOMX_DATASET_ITEM_COUNT {
        return false;
    }
    
    // 2. Verify proof path length
    if proof.siblings.len() != MERKLE_TREE_DEPTH.into() {
        return false;
    }
    if proof.directions.len() != MERKLE_TREE_DEPTH.into() {
        return false;
    }
    
    // 3. Hash the item to get leaf value
    let leaf = hash_dataset_item(*proof.item);
    
    // 4. Compute root from leaf and proof
    let computed_root = compute_merkle_root(
        leaf,
        proof.siblings.span(),
        proof.directions.span()
    );
    
    // 5. Verify computed root matches expected root
    computed_root == expected_root
}

/// Verify all Dataset access proofs for a hash computation
pub fn verify_all_dataset_accesses(proofs: @DatasetAccessProofs) -> bool {
    let expected_root = *proofs.dataset_root;
    let proof_count = proofs.proofs.len();
    
    // Must have exactly TOTAL_DATASET_ACCESSES proofs
    if proof_count != TOTAL_DATASET_ACCESSES.into() {
        return false;
    }
    
    // Verify each proof
    let mut i: usize = 0;
    loop {
        if i >= proof_count {
            break true;
        }
        
        let proof = proofs.proofs.at(i);
        if !verify_dataset_item_proof(expected_root, proof) {
            break false;
        }
        
        i += 1;
    }
}

// ============================================================
// Verification with VM Trace Binding
// ============================================================

/// Verify that accessed items match the expected addresses from VM execution
pub fn verify_access_pattern(
    proofs: @DatasetAccessProofs,
    expected_indices: Span<u64>
) -> bool {
    let proof_count = proofs.proofs.len();
    
    if proof_count != expected_indices.len() {
        return false;
    }
    
    let mut i: usize = 0;
    loop {
        if i >= proof_count {
            break true;
        }
        
        let proof = proofs.proofs.at(i);
        let expected_index = *expected_indices.at(i);
        
        // Verify the proof is for the correct item index
        if *proof.item_index != expected_index {
            break false;
        }
        
        i += 1;
    }
}

/// Complete verification: proofs + access pattern
pub fn verify_dataset_accesses_complete(
    proofs: @DatasetAccessProofs,
    expected_indices: Span<u64>
) -> bool {
    // 1. Verify all Merkle proofs are valid
    if !verify_all_dataset_accesses(proofs) {
        return false;
    }
    
    // 2. Verify access pattern matches VM trace
    if !verify_access_pattern(proofs, expected_indices) {
        return false;
    }
    
    true
}

// ============================================================
// Helper Functions
// ============================================================

/// Compute item index from memory address
/// address = (itemNumber * 64) % SCRATCHPAD_SIZE
pub fn item_index_from_address(address: u64, scratchpad_size: u64) -> u64 {
    // Reverse the address computation
    // In RandomX, address = ma XOR (r[dst_reg] & (SCRATCHPAD_SIZE - 64))
    // For Dataset access, the item index is computed differently
    address % RANDOMX_DATASET_ITEM_COUNT
}

/// Verify item index is within bounds
pub fn is_valid_item_index(index: u64) -> bool {
    index < RANDOMX_DATASET_ITEM_COUNT
}

/// Get the depth of proof required for a given dataset size
pub fn get_proof_depth(dataset_size: u64) -> u32 {
    // log2(dataset_size), rounded up
    let mut depth: u32 = 0;
    let mut size = dataset_size;
    loop {
        if size <= 1 {
            break;
        }
        size = (size + 1) / 2;
        depth += 1;
    }
    depth
}
