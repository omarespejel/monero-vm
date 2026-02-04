// ============================================================
// Tests for Merkle Proof Verification
// SECURITY-CRITICAL TESTS
// ============================================================

use monero_vm::randomx::merkle_verification::{
    DatasetItem, DatasetMerkleProof,
    hash_dataset_item, compute_merkle_root, verify_dataset_item_proof,
    is_valid_item_index, get_proof_depth,
    RANDOMX_DATASET_ITEM_COUNT, MERKLE_TREE_DEPTH,
    DATASET_ACCESSES_PER_PROGRAM, RANDOMX_PROGRAM_COUNT,
    TOTAL_DATASET_ACCESSES,
};

// ============================================================
// Constants Tests
// ============================================================

#[test]
fn test_dataset_item_count() {
    // RandomX dataset: ~34 million items
    assert(RANDOMX_DATASET_ITEM_COUNT == 34078720, 'dataset count');
}

#[test]
fn test_merkle_tree_depth() {
    // log2(34078720) ≈ 25
    assert(MERKLE_TREE_DEPTH == 25, 'tree depth');
}

#[test]
fn test_dataset_accesses_per_program() {
    // Each program accesses 8 items
    assert(DATASET_ACCESSES_PER_PROGRAM == 8, 'accesses per prog');
}

#[test]
fn test_program_count() {
    // 8 program iterations
    assert(RANDOMX_PROGRAM_COUNT == 8, 'program count');
}

#[test]
fn test_total_accesses() {
    // 8 programs × 8 accesses = 64 total
    assert(TOTAL_DATASET_ACCESSES == 64, 'total accesses');
    assert(TOTAL_DATASET_ACCESSES == DATASET_ACCESSES_PER_PROGRAM * RANDOMX_PROGRAM_COUNT, 'calc');
}

// ============================================================
// Dataset Item Hashing Tests
// ============================================================

#[test]
fn test_hash_dataset_item_deterministic() {
    let item = DatasetItem {
        r0: 0x680588a85ae222db,  // Official test vector item 0
        r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    let hash1 = hash_dataset_item(item);
    let hash2 = hash_dataset_item(item);
    
    assert(hash1 == hash2, 'hash deterministic');
}

#[test]
fn test_hash_dataset_item_different_inputs() {
    let item1 = DatasetItem {
        r0: 1, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let item2 = DatasetItem {
        r0: 2, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    let hash1 = hash_dataset_item(item1);
    let hash2 = hash_dataset_item(item2);
    
    assert(hash1 != hash2, 'diff items diff hash');
}

#[test]
fn test_hash_uses_all_registers() {
    // Changing any register should change the hash
    let base = DatasetItem {
        r0: 1, r1: 2, r2: 3, r3: 4, r4: 5, r5: 6, r6: 7, r7: 8,
    };
    
    let modified_r7 = DatasetItem {
        r0: 1, r1: 2, r2: 3, r3: 4, r4: 5, r5: 6, r6: 7, r7: 9,
    };
    
    assert(hash_dataset_item(base) != hash_dataset_item(modified_r7), 'r7 affects hash');
}

// ============================================================
// Merkle Root Computation Tests
// ============================================================

#[test]
fn test_compute_merkle_root_single_level() {
    // With empty proof, root should equal leaf
    let leaf: felt252 = 12345;
    let siblings: Array<felt252> = array![];
    let directions: Array<u8> = array![];
    
    let root = compute_merkle_root(leaf, siblings.span(), directions.span());
    assert(root == leaf, 'empty proof -> leaf');
}

#[test]
fn test_compute_merkle_root_one_sibling() {
    let leaf: felt252 = 100;
    let sibling: felt252 = 200;
    
    // Test left child (direction = 0)
    let siblings_left: Array<felt252> = array![sibling];
    let directions_left: Array<u8> = array![0];
    let root_left = compute_merkle_root(leaf, siblings_left.span(), directions_left.span());
    
    // Test right child (direction = 1)
    let siblings_right: Array<felt252> = array![sibling];
    let directions_right: Array<u8> = array![1];
    let root_right = compute_merkle_root(leaf, siblings_right.span(), directions_right.span());
    
    // Different directions should give different roots
    assert(root_left != root_right, 'direction matters');
}

#[test]
fn test_compute_merkle_root_deterministic() {
    let leaf: felt252 = 42;
    let siblings: Array<felt252> = array![1, 2, 3];
    let directions: Array<u8> = array![0, 1, 0];
    
    let root1 = compute_merkle_root(leaf, siblings.span(), directions.span());
    
    let siblings2: Array<felt252> = array![1, 2, 3];
    let directions2: Array<u8> = array![0, 1, 0];
    let root2 = compute_merkle_root(leaf, siblings2.span(), directions2.span());
    
    assert(root1 == root2, 'root deterministic');
}

// ============================================================
// Proof Verification Tests
// ============================================================

#[test]
fn test_verify_rejects_invalid_item_index() {
    // Item index >= RANDOMX_DATASET_ITEM_COUNT should fail
    let item = DatasetItem {
        r0: 0, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // Create proof with invalid index
    let mut siblings: Array<felt252> = ArrayTrait::new();
    let mut directions: Array<u8> = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i >= MERKLE_TREE_DEPTH {
            break;
        }
        siblings.append(0);
        directions.append(0);
        i += 1;
    }
    
    let proof = DatasetMerkleProof {
        item_index: RANDOMX_DATASET_ITEM_COUNT + 1,  // Invalid!
        item: item,
        siblings: siblings,
        directions: directions,
    };
    
    let result = verify_dataset_item_proof(0, @proof);
    assert(!result, 'reject invalid index');
}

#[test]
fn test_verify_rejects_wrong_proof_length() {
    let item = DatasetItem {
        r0: 0, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // Wrong number of siblings (should be 25, we give 3)
    let siblings: Array<felt252> = array![1, 2, 3];
    let directions: Array<u8> = array![0, 0, 0];
    
    let proof = DatasetMerkleProof {
        item_index: 0,
        item: item,
        siblings: siblings,
        directions: directions,
    };
    
    let result = verify_dataset_item_proof(0, @proof);
    assert(!result, 'reject wrong length');
}

// ============================================================
// Valid Item Index Tests
// ============================================================

#[test]
fn test_is_valid_item_index_zero() {
    assert(is_valid_item_index(0), 'index 0 valid');
}

#[test]
fn test_is_valid_item_index_max() {
    assert(is_valid_item_index(RANDOMX_DATASET_ITEM_COUNT - 1), 'max index valid');
}

#[test]
fn test_is_valid_item_index_overflow() {
    assert(!is_valid_item_index(RANDOMX_DATASET_ITEM_COUNT), 'overflow invalid');
    assert(!is_valid_item_index(RANDOMX_DATASET_ITEM_COUNT + 1000), 'way over invalid');
}

// ============================================================
// Proof Depth Tests
// ============================================================

#[test]
fn test_get_proof_depth_small() {
    // depth of 1 item = 0
    assert(get_proof_depth(1) == 0, 'depth(1)');
    // depth of 2 items = 1
    assert(get_proof_depth(2) == 1, 'depth(2)');
    // depth of 4 items = 2
    assert(get_proof_depth(4) == 2, 'depth(4)');
}

#[test]
fn test_get_proof_depth_non_power_of_two() {
    // depth of 3 items = 2 (rounds up)
    assert(get_proof_depth(3) == 2, 'depth(3)');
    // depth of 5 items = 3
    assert(get_proof_depth(5) == 3, 'depth(5)');
}

// ============================================================
// Security Tests
// ============================================================

#[test]
fn test_different_roots_reject_same_proof() {
    // A valid proof for root A should fail for root B
    let item = DatasetItem {
        r0: 123, r1: 456, r2: 789, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    let mut siblings: Array<felt252> = ArrayTrait::new();
    let mut directions: Array<u8> = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i >= MERKLE_TREE_DEPTH {
            break;
        }
        siblings.append(i.into());
        directions.append(0);
        i += 1;
    }
    
    let proof = DatasetMerkleProof {
        item_index: 0,
        item: item,
        siblings: siblings,
        directions: directions,
    };
    
    // Compute the actual root for this proof
    let leaf = hash_dataset_item(item);
    let computed_root = compute_merkle_root(leaf, proof.siblings.span(), proof.directions.span());
    
    // Verify passes with correct root
    let result_correct = verify_dataset_item_proof(computed_root, @proof);
    assert(result_correct, 'correct root passes');
    
    // Verify fails with wrong root
    let wrong_root = computed_root + 1;
    let result_wrong = verify_dataset_item_proof(wrong_root, @proof);
    assert(!result_wrong, 'wrong root fails');
}
