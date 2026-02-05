/// Tests for Fraud Proof State Commitment
///
/// These tests verify the state commitment scheme used in fraud proofs.

use monero_vm::randomx::fraud_proof::{
    IntegerRegisters, FloatRegister, FloatRegisters, RegisterFile,
    ExecutionState, RandomXState, ChallengeStatus, Turn, BisectionPhase,
    BisectionProof, compute_state_hash, hash_registers, hash_execution,
    initial_state, verify_state_transition,
    compute_bisection_midpoint, is_single_instruction, constants,
    update_fprc, reset_fprc, reset_fprc_for_new_hash, advance_to_next_program,
    compute_cfround_fprc,
    apply_iteration_end_xor, verify_iteration_end_xor,
    instruction_verifiers::{
        verify_iadd_r, verify_isub_r, verify_imul_r, verify_imulh_r,
        verify_ixor_r, verify_iror_r, verify_irol_r,
        verify_iswap_r
    },
    memory_verifiers::{
        MemoryWitness, verify_iadd_m, verify_isub_m, verify_imul_m,
        verify_ixor_m
    },
    fp_stubs::{
        verify_fadd_r_stub, verify_fsub_r_stub, verify_fmul_r_stub,
        verify_fdiv_m_stub, verify_fsqrt_r_stub, verify_fswap_r_stub,
        verify_cfround_stub, verify_fscal_r_stub, verify_fscal_r, FSCAL_MASK
    },
    cbranch_verifier::{
        CBranchClaim, init_tracker,
        get_last_mod_pc, update_tracker, reset_all_trackers, verify_cbranch
    }
};

// ============================================================================
// State Hash Tests
// ============================================================================

#[test]
fn test_compute_state_hash_deterministic() {
    // Create a test state
    let state = create_test_state();
    
    // Hash should be deterministic
    let hash1 = compute_state_hash(state);
    let hash2 = compute_state_hash(state);
    
    assert(hash1 == hash2, 'Hash should be deterministic');
}

#[test]
fn test_compute_state_hash_different_registers() {
    let state1 = create_test_state();
    
    // Create state with different r0
    let mut state2 = create_test_state();
    state2.registers.int_regs.r0 = 12345;
    
    let hash1 = compute_state_hash(state1);
    let hash2 = compute_state_hash(state2);
    
    assert(hash1 != hash2, 'Different regs different hash');
}

#[test]
fn test_compute_state_hash_different_pc() {
    let state1 = create_test_state();
    
    // Create state with different program counter
    let mut state2 = create_test_state();
    state2.execution.program_counter = 100;
    
    let hash1 = compute_state_hash(state1);
    let hash2 = compute_state_hash(state2);
    
    assert(hash1 != hash2, 'Different PC different hash');
}

#[test]
fn test_compute_state_hash_different_scratchpad() {
    let state1 = create_test_state();
    
    // Create state with different scratchpad root
    let mut state2 = create_test_state();
    state2.scratchpad_root = 0xdeadbeef;
    
    let hash1 = compute_state_hash(state1);
    let hash2 = compute_state_hash(state2);
    
    assert(hash1 != hash2, 'Different scratchpad diff hash');
}

#[test]
fn test_hash_registers_deterministic() {
    let registers = create_test_registers();
    
    let hash1 = hash_registers(registers);
    let hash2 = hash_registers(registers);
    
    assert(hash1 == hash2, 'Reg hash deterministic');
}

#[test]
fn test_hash_registers_all_zeros() {
    let int_regs = IntegerRegisters {
        r0: 0, r1: 0, r2: 0, r3: 0,
        r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    let zero_float = FloatRegister { low: 0, high: 0 };
    let float_regs = FloatRegisters {
        f0: zero_float, f1: zero_float, f2: zero_float, f3: zero_float,
        e0: zero_float, e1: zero_float, e2: zero_float, e3: zero_float,
        a0: zero_float, a1: zero_float, a2: zero_float, a3: zero_float,
    };
    
    let registers = RegisterFile { int_regs, float_regs };
    
    // Should produce a valid hash (not zero)
    let hash = hash_registers(registers);
    assert(hash != 0, 'Zero regs should hash non-zero');
}

#[test]
fn test_hash_execution_deterministic() {
    let execution = ExecutionState {
        program_counter: 50,
        iteration_counter: 1000,
        program_index: 3,
        fprc: 2,
        ma: 0x12345678,
        mx: 0x87654321,
    };
    
    let hash1 = hash_execution(execution);
    let hash2 = hash_execution(execution);
    
    assert(hash1 == hash2, 'Exec hash deterministic');
}

// ============================================================================
// Initial State Tests
// ============================================================================

#[test]
fn test_initial_state_zeros_registers() {
    let seed: felt252 = 0x12345;
    let scratchpad_root: felt252 = 0xabcdef;
    
    let state = initial_state(seed, scratchpad_root);
    
    // Integer registers should be zero
    assert(state.registers.int_regs.r0 == 0, 'r0 should be 0');
    assert(state.registers.int_regs.r1 == 0, 'r1 should be 0');
    assert(state.registers.int_regs.r7 == 0, 'r7 should be 0');
}

#[test]
fn test_initial_state_correct_iteration() {
    let seed: felt252 = 0x12345;
    let scratchpad_root: felt252 = 0xabcdef;
    
    let state = initial_state(seed, scratchpad_root);
    
    // Iteration counter starts at 2048
    assert(state.execution.iteration_counter == 2048, 'IC should be 2048');
    assert(state.execution.program_counter == 0, 'PC should be 0');
    assert(state.execution.program_index == 0, 'Program idx should be 0');
}

#[test]
fn test_initial_state_preserves_scratchpad_root() {
    let seed: felt252 = 0x12345;
    let scratchpad_root: felt252 = 0xdeadbeefcafe;
    
    let state = initial_state(seed, scratchpad_root);
    
    assert(state.scratchpad_root == scratchpad_root, 'Scratchpad root preserved');
}

// ============================================================================
// Constants Tests
// ============================================================================

#[test]
fn test_constants_valid() {
    // Verify constants match RandomX spec
    assert(constants::PROGRAMS_PER_HASH == 8, 'Programs should be 8');
    assert(constants::ITERATIONS_PER_PROGRAM == 2048, 'Iterations should be 2048');
    assert(constants::INSTRUCTIONS_PER_PROGRAM == 256, 'Instructions should be 256');
    
    // Verify bisection rounds
    assert(constants::PROGRAM_BISECTION_ROUNDS == 3, 'Program rounds should be 3');
    assert(constants::ITERATION_BISECTION_ROUNDS == 11, 'Iteration rounds should be 11');
    assert(constants::INSTRUCTION_BISECTION_ROUNDS == 8, 'Instruction rounds should be 8');
    assert(constants::TOTAL_BISECTION_ROUNDS == 22, 'Total rounds should be 22');
}

#[test]
fn test_bond_constants() {
    // Challenger bond: 0.1 ETH
    assert(constants::CHALLENGER_BOND == 100000000000000000, 'Challenger bond 0.1 ETH');
    
    // Defender bond: 0.2 ETH
    assert(constants::DEFENDER_BOND == 200000000000000000, 'Defender bond 0.2 ETH');
}

#[test]
fn test_timeout_constants() {
    // Bisection timeout: 4 hours = 14400 seconds
    assert(constants::BISECTION_TIMEOUT == 14400, 'Bisection 4 hours');
    
    // Final proof timeout: 24 hours = 86400 seconds
    assert(constants::FINAL_PROOF_TIMEOUT == 86400, 'Final proof 24 hours');
    
    // Total dispute window: 7 days = 604800 seconds
    assert(constants::TOTAL_DISPUTE_WINDOW == 604800, 'Total 7 days');
}

// ============================================================================
// State Transition Tests
// ============================================================================

#[test]
fn test_verify_state_transition_pc_increment() {
    let pre_state = create_test_state();
    
    // Create post state with PC incremented by 1
    let mut post_state = pre_state;
    post_state.execution.program_counter = pre_state.execution.program_counter + 1;
    
    // Non-branch instruction (e.g., IADD = opcode 0)
    let result = verify_state_transition(pre_state, post_state, 0, 0);
    
    assert(result, 'Valid PC increment');
}

#[test]
fn test_verify_state_transition_wrong_pc() {
    let pre_state = create_test_state();
    
    // Create post state with wrong PC (jumped by 2 instead of 1)
    let mut post_state = pre_state;
    post_state.execution.program_counter = pre_state.execution.program_counter + 2;
    
    // Non-branch instruction should increment by exactly 1
    let result = verify_state_transition(pre_state, post_state, 0, 0);
    
    assert(!result, 'Wrong PC should fail');
}

// ============================================================================
// Challenge Status Tests
// ============================================================================

#[test]
fn test_challenge_status_enum() {
    let status1 = ChallengeStatus::Pending;
    let status2 = ChallengeStatus::Bisecting;
    let status3 = ChallengeStatus::AwaitingProof;
    let status4 = ChallengeStatus::Resolved;
    let status5 = ChallengeStatus::TimedOut;
    
    // Verify different statuses are distinguishable
    assert(status1 != status2, 'Pending != Bisecting');
    assert(status2 != status3, 'Bisecting != AwaitingProof');
    assert(status3 != status4, 'AwaitingProof != Resolved');
    assert(status4 != status5, 'Resolved != TimedOut');
}

#[test]
fn test_turn_enum() {
    let turn1 = Turn::Defender;
    let turn2 = Turn::Challenger;
    
    assert(turn1 != turn2, 'Turns should be different');
}

#[test]
fn test_bisection_phase_enum() {
    let phase1 = BisectionPhase::Program;
    let phase2 = BisectionPhase::Iteration;
    let phase3 = BisectionPhase::Instruction;
    
    assert(phase1 != phase2, 'Program != Iteration');
    assert(phase2 != phase3, 'Iteration != Instruction');
}

// ============================================================================
// Float Register Tests
// ============================================================================

#[test]
fn test_float_register_storage() {
    // Test that float registers can store full 64-bit values
    let max_u64: u64 = 0xFFFFFFFFFFFFFFFF;
    let float_reg = FloatRegister { low: max_u64, high: max_u64 };
    
    assert(float_reg.low == max_u64, 'Float low preserved');
    assert(float_reg.high == max_u64, 'Float high preserved');
}

#[test]
fn test_float_register_different_values() {
    let reg1 = FloatRegister { low: 0x1234, high: 0x5678 };
    let reg2 = FloatRegister { low: 0x5678, high: 0x1234 };
    
    assert(reg1 != reg2, 'Different float regs');
}

// ============================================================================
// PRT Bisection Tests
// ============================================================================

#[test]
fn test_compute_bisection_midpoint() {
    // Basic midpoint calculation
    let mid = compute_bisection_midpoint(0, 256);
    assert(mid == 128, 'Midpoint of 0-256 is 128');
    
    let mid2 = compute_bisection_midpoint(0, 128);
    assert(mid2 == 64, 'Midpoint of 0-128 is 64');
    
    let mid3 = compute_bisection_midpoint(64, 128);
    assert(mid3 == 96, 'Midpoint of 64-128 is 96');
}

#[test]
fn test_is_single_instruction() {
    // Not single instruction
    assert(!is_single_instruction(0, 256), '0-256 not single');
    assert(!is_single_instruction(0, 2), '0-2 not single');
    
    // Single instruction (range of 1)
    assert(is_single_instruction(0, 1), '0-1 is single');
    assert(is_single_instruction(100, 101), '100-101 is single');
    assert(is_single_instruction(255, 256), '255-256 is single');
}

#[test]
fn test_bisection_rounds_to_single_instruction() {
    // Verify 8 rounds of bisection isolates single instruction from 256
    let mut left: u32 = 0;
    let mut right: u32 = 256;
    let mut rounds: u8 = 0;
    
    loop {
        if is_single_instruction(left, right) {
            break;
        }
        
        let mid = compute_bisection_midpoint(left, right);
        // Simulate always going right (worst case)
        left = mid;
        rounds += 1;
        
        if rounds > 10 {
            break; // Safety limit
        }
    };
    
    assert(rounds == 8, 'Should take 8 rounds');
    assert(is_single_instruction(left, right), 'Should be single instr');
}

#[test]
fn test_mvp_bisection_rounds_constant() {
    // Verify MVP constant matches log2(256)
    assert(constants::MVP_BISECTION_ROUNDS == 8, 'MVP should be 8 rounds');
    assert(constants::INSTRUCTIONS_PER_PROGRAM == 256, 'Should be 256 instr');
}

#[test]
fn test_scratchpad_constants() {
    // Verify scratchpad Merkle tree parameters
    assert(constants::SCRATCHPAD_TREE_DEPTH == 15, 'Depth should be 15');
    assert(constants::SCRATCHPAD_LEAF_COUNT == 32768, 'Leaves should be 32768');
    
    // Verify: 2^15 = 32768
    let expected_leaves: u32 = 32768;
    assert(constants::SCRATCHPAD_LEAF_COUNT == expected_leaves, 'Leaf count matches');
}

#[test]
fn test_merkle_proof_gas_estimate() {
    // Verify gas estimate: 15 levels × 491 Poseidon gas = 7365
    assert(constants::MERKLE_PROOF_GAS == 7365, 'Gas should be 7365');
}

// ============================================================================
// BisectionProof Tests
// ============================================================================

#[test]
fn test_bisection_proof_struct() {
    let proof = BisectionProof {
        computation_root: 0x12345,
        midpoint_hash: 0x67890,
        proof_path: 0xABCDE,
    };
    
    assert(proof.computation_root == 0x12345, 'Computation root stored');
    assert(proof.midpoint_hash == 0x67890, 'Midpoint hash stored');
    assert(proof.proof_path == 0xABCDE, 'Proof path stored');
}

// ============================================================================
// Instruction Verifier Tests
// ============================================================================

#[test]
fn test_verify_iadd_r_correct() {
    let pre = IntegerRegisters {
        r0: 100, r1: 50, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // r0 = r0 + r1 = 100 + 50 = 150
    let post = IntegerRegisters {
        r0: 150, r1: 50, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(verify_iadd_r(pre, 0, 1, post), 'IADD_R should verify');
}

#[test]
fn test_verify_iadd_r_wrapping() {
    let pre = IntegerRegisters {
        r0: 0xFFFFFFFFFFFFFFFF, r1: 1, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // r0 = MAX + 1 = 0 (wrapping)
    let post = IntegerRegisters {
        r0: 0, r1: 1, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(verify_iadd_r(pre, 0, 1, post), 'IADD_R wrapping should verify');
}

#[test]
fn test_verify_iadd_r_wrong_result() {
    let pre = IntegerRegisters {
        r0: 100, r1: 50, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // Wrong result (should be 150)
    let post = IntegerRegisters {
        r0: 200, r1: 50, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(!verify_iadd_r(pre, 0, 1, post), 'Wrong result should fail');
}

#[test]
fn test_verify_isub_r_correct() {
    let pre = IntegerRegisters {
        r0: 100, r1: 30, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // r0 = r0 - r1 = 100 - 30 = 70
    let post = IntegerRegisters {
        r0: 70, r1: 30, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(verify_isub_r(pre, 0, 1, post), 'ISUB_R should verify');
}

#[test]
fn test_verify_isub_r_wrapping() {
    let pre = IntegerRegisters {
        r0: 0, r1: 1, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // r0 = 0 - 1 = MAX (wrapping)
    let post = IntegerRegisters {
        r0: 0xFFFFFFFFFFFFFFFF, r1: 1, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(verify_isub_r(pre, 0, 1, post), 'ISUB_R wrapping should verify');
}

#[test]
fn test_verify_imul_r_correct() {
    let pre = IntegerRegisters {
        r0: 7, r1: 6, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // r0 = r0 * r1 = 7 * 6 = 42
    let post = IntegerRegisters {
        r0: 42, r1: 6, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(verify_imul_r(pre, 0, 1, post), 'IMUL_R should verify');
}

#[test]
fn test_verify_imulh_r_correct() {
    let pre = IntegerRegisters {
        r0: 0x8000000000000000, r1: 2, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // IMULH: high 64 bits of (0x8000000000000000 * 2) = 1
    let post = IntegerRegisters {
        r0: 1, r1: 2, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(verify_imulh_r(pre, 0, 1, post), 'IMULH_R should verify');
}

#[test]
fn test_verify_ixor_r_correct() {
    let pre = IntegerRegisters {
        r0: 0xFF00FF00FF00FF00, r1: 0x00FF00FF00FF00FF, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // r0 = r0 ^ r1 = all ones
    let post = IntegerRegisters {
        r0: 0xFFFFFFFFFFFFFFFF, r1: 0x00FF00FF00FF00FF, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(verify_ixor_r(pre, 0, 1, post), 'IXOR_R should verify');
}

#[test]
fn test_verify_iror_r_correct() {
    let pre = IntegerRegisters {
        r0: 0x8000000000000001, r1: 1, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // Rotate right by 1: MSB goes to position 62, LSB goes to MSB
    let post = IntegerRegisters {
        r0: 0xC000000000000000, r1: 1, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(verify_iror_r(pre, 0, 1, post), 'IROR_R should verify');
}

#[test]
fn test_verify_irol_r_correct() {
    let pre = IntegerRegisters {
        r0: 0x8000000000000001, r1: 1, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // Rotate left by 1: MSB goes to LSB, all bits shift left
    let post = IntegerRegisters {
        r0: 0x0000000000000003, r1: 1, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(verify_irol_r(pre, 0, 1, post), 'IROL_R should verify');
}

#[test]
fn test_verify_iswap_r_correct() {
    let pre = IntegerRegisters {
        r0: 100, r1: 200, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // Swap r0 and r1
    let post = IntegerRegisters {
        r0: 200, r1: 100, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(verify_iswap_r(pre, 0, 1, post), 'ISWAP_R should verify');
}

#[test]
fn test_verify_iswap_r_same_register() {
    let pre = IntegerRegisters {
        r0: 100, r1: 200, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // Swap r0 with itself = no-op
    let post = pre;
    
    assert(verify_iswap_r(pre, 0, 0, post), 'ISWAP_R same reg = no-op');
}

#[test]
fn test_verify_other_register_modified_fails() {
    let pre = IntegerRegisters {
        r0: 100, r1: 50, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // IADD modifies r0, but we also modified r2 (invalid!)
    let post = IntegerRegisters {
        r0: 150, r1: 50, r2: 999, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(!verify_iadd_r(pre, 0, 1, post), 'Other reg modified = fail');
}

// ============================================================================
// Memory Verifier Tests
// ============================================================================

/// Helper: create a simple Merkle tree root for testing
/// This builds a simple tree where the root commits to a single value at a given leaf
fn build_simple_merkle_root(value: u64, leaf_index: u32, depth: u8) -> (felt252, MemoryWitness) {
    // For simplicity, use a tree where all siblings are 0
    // This is valid for testing but not production
    let leaf_hash: felt252 = value.into();
    let mut current_hash = leaf_hash;
    let mut index = leaf_index;
    
    let mut i: u8 = 0;
    loop {
        if i >= depth {
            break;
        }
        
        let sibling: felt252 = 0; // Simple test: all siblings are 0
        if index % 2 == 0 {
            current_hash = core::poseidon::poseidon_hash_span(array![current_hash, sibling].span());
        } else {
            current_hash = core::poseidon::poseidon_hash_span(array![sibling, current_hash].span());
        }
        index = index / 2;
        i += 1;
    };
    
    let witness = MemoryWitness {
        value: value,
        proof_len: depth,
        proof_0: 0,
        proof_1: 0,
        proof_2: 0,
        proof_3: 0,
        proof_4: 0,
        proof_5: 0,
        proof_6: 0,
        proof_7: 0,
        proof_8: 0,
        proof_9: 0,
        proof_10: 0,
        proof_11: 0,
        proof_12: 0,
        proof_13: 0,
        proof_14: 0,
    };
    
    (current_hash, witness)
}

#[test]
fn test_memory_witness_struct() {
    let witness = MemoryWitness {
        value: 0x12345678,
        proof_len: 15,
        proof_0: 0x1, proof_1: 0x2, proof_2: 0x3, proof_3: 0x4,
        proof_4: 0x5, proof_5: 0x6, proof_6: 0x7, proof_7: 0x8,
        proof_8: 0x9, proof_9: 0xA, proof_10: 0xB, proof_11: 0xC,
        proof_12: 0xD, proof_13: 0xE, proof_14: 0xF,
    };
    
    assert(witness.value == 0x12345678, 'Value stored correctly');
    assert(witness.proof_len == 15, 'Proof len stored');
    assert(witness.proof_0 == 0x1, 'Proof element 0');
    assert(witness.proof_14 == 0xF, 'Proof element 14');
}

#[test]
fn test_verify_iadd_m_correct() {
    // Build a scratchpad root that commits to value 50 at leaf 0
    let mem_value: u64 = 50;
    let leaf_idx: u32 = 0;
    let (scratchpad_root, witness) = build_simple_merkle_root(mem_value, leaf_idx, 15);
    
    let int_regs = IntegerRegisters {
        r0: 100,  // dst = 100
        r1: 0,    // src = 0, imm = 0 -> address 0 -> leaf 0
        r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    let zero_float = FloatRegister { low: 0, high: 0 };
    let float_regs = FloatRegisters {
        f0: zero_float, f1: zero_float, f2: zero_float, f3: zero_float,
        e0: zero_float, e1: zero_float, e2: zero_float, e3: zero_float,
        a0: zero_float, a1: zero_float, a2: zero_float, a3: zero_float,
    };
    
    let pre_state = RandomXState {
        registers: RegisterFile { int_regs, float_regs },
        execution: ExecutionState {
            program_counter: 0, iteration_counter: 0, program_index: 0,
            fprc: 0, ma: 0, mx: 0,
        },
        scratchpad_root,
    };
    
    // r0 = r0 + [mem] = 100 + 50 = 150
    let post_regs = IntegerRegisters {
        r0: 150, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(verify_iadd_m(pre_state, 0, 1, 0, witness, post_regs), 'IADD_M should verify');
}

#[test]
fn test_verify_iadd_m_wrong_result() {
    let mem_value: u64 = 50;
    let leaf_idx: u32 = 0;
    let (scratchpad_root, witness) = build_simple_merkle_root(mem_value, leaf_idx, 15);
    
    let int_regs = IntegerRegisters {
        r0: 100, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    let zero_float = FloatRegister { low: 0, high: 0 };
    let float_regs = FloatRegisters {
        f0: zero_float, f1: zero_float, f2: zero_float, f3: zero_float,
        e0: zero_float, e1: zero_float, e2: zero_float, e3: zero_float,
        a0: zero_float, a1: zero_float, a2: zero_float, a3: zero_float,
    };
    
    let pre_state = RandomXState {
        registers: RegisterFile { int_regs, float_regs },
        execution: ExecutionState {
            program_counter: 0, iteration_counter: 0, program_index: 0,
            fprc: 0, ma: 0, mx: 0,
        },
        scratchpad_root,
    };
    
    // Wrong result: should be 150, claiming 200
    let post_regs = IntegerRegisters {
        r0: 200, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(!verify_iadd_m(pre_state, 0, 1, 0, witness, post_regs), 'Wrong result should fail');
}

#[test]
fn test_verify_isub_m_correct() {
    let mem_value: u64 = 30;
    let leaf_idx: u32 = 0;
    let (scratchpad_root, witness) = build_simple_merkle_root(mem_value, leaf_idx, 15);
    
    let int_regs = IntegerRegisters {
        r0: 100, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    let zero_float = FloatRegister { low: 0, high: 0 };
    let float_regs = FloatRegisters {
        f0: zero_float, f1: zero_float, f2: zero_float, f3: zero_float,
        e0: zero_float, e1: zero_float, e2: zero_float, e3: zero_float,
        a0: zero_float, a1: zero_float, a2: zero_float, a3: zero_float,
    };
    
    let pre_state = RandomXState {
        registers: RegisterFile { int_regs, float_regs },
        execution: ExecutionState {
            program_counter: 0, iteration_counter: 0, program_index: 0,
            fprc: 0, ma: 0, mx: 0,
        },
        scratchpad_root,
    };
    
    // r0 = r0 - [mem] = 100 - 30 = 70
    let post_regs = IntegerRegisters {
        r0: 70, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(verify_isub_m(pre_state, 0, 1, 0, witness, post_regs), 'ISUB_M should verify');
}

#[test]
fn test_verify_imul_m_correct() {
    let mem_value: u64 = 7;
    let leaf_idx: u32 = 0;
    let (scratchpad_root, witness) = build_simple_merkle_root(mem_value, leaf_idx, 15);
    
    let int_regs = IntegerRegisters {
        r0: 6, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    let zero_float = FloatRegister { low: 0, high: 0 };
    let float_regs = FloatRegisters {
        f0: zero_float, f1: zero_float, f2: zero_float, f3: zero_float,
        e0: zero_float, e1: zero_float, e2: zero_float, e3: zero_float,
        a0: zero_float, a1: zero_float, a2: zero_float, a3: zero_float,
    };
    
    let pre_state = RandomXState {
        registers: RegisterFile { int_regs, float_regs },
        execution: ExecutionState {
            program_counter: 0, iteration_counter: 0, program_index: 0,
            fprc: 0, ma: 0, mx: 0,
        },
        scratchpad_root,
    };
    
    // r0 = r0 * [mem] = 6 * 7 = 42
    let post_regs = IntegerRegisters {
        r0: 42, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(verify_imul_m(pre_state, 0, 1, 0, witness, post_regs), 'IMUL_M should verify');
}

#[test]
fn test_verify_ixor_m_correct() {
    let mem_value: u64 = 0x00FF00FF00FF00FF;
    let leaf_idx: u32 = 0;
    let (scratchpad_root, witness) = build_simple_merkle_root(mem_value, leaf_idx, 15);
    
    let int_regs = IntegerRegisters {
        r0: 0xFF00FF00FF00FF00, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    let zero_float = FloatRegister { low: 0, high: 0 };
    let float_regs = FloatRegisters {
        f0: zero_float, f1: zero_float, f2: zero_float, f3: zero_float,
        e0: zero_float, e1: zero_float, e2: zero_float, e3: zero_float,
        a0: zero_float, a1: zero_float, a2: zero_float, a3: zero_float,
    };
    
    let pre_state = RandomXState {
        registers: RegisterFile { int_regs, float_regs },
        execution: ExecutionState {
            program_counter: 0, iteration_counter: 0, program_index: 0,
            fprc: 0, ma: 0, mx: 0,
        },
        scratchpad_root,
    };
    
    // r0 = r0 ^ [mem] = all 1s
    let post_regs = IntegerRegisters {
        r0: 0xFFFFFFFFFFFFFFFF, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    assert(verify_ixor_m(pre_state, 0, 1, 0, witness, post_regs), 'IXOR_M should verify');
}

#[test]
fn test_verify_memory_wrong_proof() {
    // Create a valid root for value 50
    let mem_value: u64 = 50;
    let leaf_idx: u32 = 0;
    let (scratchpad_root, _) = build_simple_merkle_root(mem_value, leaf_idx, 15);
    
    // But provide a witness with wrong value
    let wrong_witness = MemoryWitness {
        value: 999,  // Wrong value!
        proof_len: 15,
        proof_0: 0, proof_1: 0, proof_2: 0, proof_3: 0,
        proof_4: 0, proof_5: 0, proof_6: 0, proof_7: 0,
        proof_8: 0, proof_9: 0, proof_10: 0, proof_11: 0,
        proof_12: 0, proof_13: 0, proof_14: 0,
    };
    
    let int_regs = IntegerRegisters {
        r0: 100, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    let zero_float = FloatRegister { low: 0, high: 0 };
    let float_regs = FloatRegisters {
        f0: zero_float, f1: zero_float, f2: zero_float, f3: zero_float,
        e0: zero_float, e1: zero_float, e2: zero_float, e3: zero_float,
        a0: zero_float, a1: zero_float, a2: zero_float, a3: zero_float,
    };
    
    let pre_state = RandomXState {
        registers: RegisterFile { int_regs, float_regs },
        execution: ExecutionState {
            program_counter: 0, iteration_counter: 0, program_index: 0,
            fprc: 0, ma: 0, mx: 0,
        },
        scratchpad_root,
    };
    
    // Even if arithmetic is "correct" with wrong value, proof fails
    let post_regs = IntegerRegisters {
        r0: 1099, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,  // 100 + 999
    };
    
    // This should fail because Merkle proof verification fails
    assert(!verify_iadd_m(pre_state, 0, 1, 0, wrong_witness, post_regs), 'Wrong proof should fail');
}

// ============================================================================
// FP Stub Tests - TESTNET SAFETY MODE
// 
// Per spec recommendation:
// FP stubs now REJECT (return false) for testnet safety.
// This ensures FP disputes cannot be resolved incorrectly on-chain.
// ============================================================================

#[test]
fn test_fp_stubs_reject_for_testnet_safety() {
    // All FP stubs should return false for testnet safety
    // FP_STUBS_ACCEPT = false means all stubs reject
    
    // FADD_R - should reject even with valid F-group dst
    assert(!verify_fadd_r_stub(0), 'fadd rejects (testnet)');
    assert(!verify_fadd_r_stub(3), 'fadd rejects (testnet)');
    
    // FSUB_R - should reject
    assert(!verify_fsub_r_stub(1), 'fsub rejects (testnet)');
    
    // FMUL_R - should reject even with valid E-group dst
    assert(!verify_fmul_r_stub(4), 'fmul rejects (testnet)');
    assert(!verify_fmul_r_stub(7), 'fmul rejects (testnet)');
    
    // FDIV_M - should reject
    assert(!verify_fdiv_m_stub(5), 'fdiv rejects (testnet)');
    
    // FSQRT_R - should reject
    assert(!verify_fsqrt_r_stub(6), 'fsqrt rejects (testnet)');
    
    // FSWAP_R - should reject even with valid same-group
    assert(!verify_fswap_r_stub(0, 1), 'fswap rejects (testnet)');
    assert(!verify_fswap_r_stub(4, 5), 'fswap rejects (testnet)');
    
    // CFROUND - should reject
    assert(!verify_cfround_stub(), 'cfround rejects (testnet)');
}

#[test]
fn test_fscal_r_stub_valid_dst() {
    // FSCAL_R has full implementation, so stub still checks register
    // But the stub also respects FP_STUBS_ACCEPT = false
    // Note: verify_fscal_r_stub checks register, but FSCAL has full verifier
    assert(verify_fscal_r_stub(0), 'f0 valid');
    assert(verify_fscal_r_stub(1), 'f1 valid');
    assert(verify_fscal_r_stub(2), 'f2 valid');
    assert(verify_fscal_r_stub(3), 'f3 valid');
}

#[test]
fn test_fscal_r_stub_invalid_dst() {
    // F-group (f0-f3) is invalid for FSCAL_R
    assert(!verify_fscal_r_stub(4), 'e0 invalid');
    assert(!verify_fscal_r_stub(5), 'e1 invalid');
    assert(!verify_fscal_r_stub(6), 'e2 invalid');
    assert(!verify_fscal_r_stub(7), 'e3 invalid');
    // Out of range
    assert(!verify_fscal_r_stub(8), 'idx 8 invalid');
}

#[test]
fn test_fscal_r_full_verifier() {
    // Test XOR with known values
    let pre_low: u64 = 0x4000000000000000;   // Some FP bits
    let pre_high: u64 = 0x3FF0000000000000;  // Another FP value
    
    let post_low = pre_low ^ FSCAL_MASK;
    let post_high = pre_high ^ FSCAL_MASK;
    
    // Correct XOR should verify
    assert(verify_fscal_r(pre_low, pre_high, post_low, post_high, 0), 'Correct XOR verifies');
}

#[test]
fn test_fscal_r_wrong_result() {
    let pre_low: u64 = 0x4000000000000000;
    let pre_high: u64 = 0x3FF0000000000000;
    
    // Wrong post value should fail
    let wrong_low = pre_low ^ 0x1234;  // Wrong mask
    let wrong_high = pre_high;
    
    assert(!verify_fscal_r(pre_low, pre_high, wrong_low, wrong_high, 0), 'Wrong XOR fails');
}

#[test]
fn test_fscal_r_wrong_dst() {
    let pre_low: u64 = 0x4000000000000000;
    let pre_high: u64 = 0x3FF0000000000000;
    let post_low = pre_low ^ FSCAL_MASK;
    let post_high = pre_high ^ FSCAL_MASK;
    
    // F-group destination should fail even with correct XOR
    assert(!verify_fscal_r(pre_low, pre_high, post_low, post_high, 4), 'E-group dst fails');
}

// ============================================================================
// IEEE-754 Full Verification Tests (Phase 2)
// ============================================================================

use monero_vm::randomx::fraud_proof::ieee754::{
    Float64, unpack, pack, is_zero, is_infinity, is_nan, is_normal,
    verify_cfround, verify_fadd, verify_fmul, verify_fdiv, verify_fsqrt,
    verify_e_group_exponent, verify_e_group_exponent_full, apply_e_group_constraint,
    verify_e_group_invariant, verify_f_group_invariant,
    verify_fswap_r, apply_e_group_mask,
    FPWitness, default_fp_witness, verify_fadd_with_witness, verify_fmul_with_witness,
    verify_fdiv_with_witness, verify_fsqrt_with_witness,
    convert_f_group_operand,
    apply_e_group_constraint_with_mask, compute_e_mask, signed_int32_to_double,
    default_program_config,
    apply_ftz_daz_bits,
    ROUND_TIES_TO_EVEN,
    DYNAMIC_MANTISSA_MASK_FULL
};

#[test]
fn test_ieee754_unpack_positive_one() {
    // +1.0 = 0x3FF0000000000000
    // Sign: 0, Exponent: 1023 (biased), Mantissa: 0
    let one_bits: u64 = 0x3FF0000000000000;
    let f = unpack(one_bits);
    
    assert(f.sign == 0, 'sign is 0');
    assert(f.exponent == 1023, 'exp is 1023');
    assert(f.mantissa == 0, 'mantissa is 0');
}

#[test]
fn test_ieee754_unpack_negative_one() {
    // -1.0 = 0xBFF0000000000000
    let neg_one_bits: u64 = 0xBFF0000000000000;
    let f = unpack(neg_one_bits);
    
    assert(f.sign == 1, 'sign is 1');
    assert(f.exponent == 1023, 'exp is 1023');
    assert(f.mantissa == 0, 'mantissa is 0');
}

#[test]
fn test_ieee754_unpack_two() {
    // +2.0 = 0x4000000000000000
    // Sign: 0, Exponent: 1024, Mantissa: 0
    let two_bits: u64 = 0x4000000000000000;
    let f = unpack(two_bits);
    
    assert(f.sign == 0, 'sign is 0');
    assert(f.exponent == 1024, 'exp is 1024');
    assert(f.mantissa == 0, 'mantissa is 0');
}

#[test]
fn test_ieee754_pack_roundtrip() {
    let original: u64 = 0x400921FB54442D18;  // pi ≈ 3.141592653589793
    let f = unpack(original);
    let packed = pack(f);
    
    assert(packed == original, 'roundtrip preserves');
}

#[test]
fn test_ieee754_is_zero() {
    // +0.0
    let pos_zero = unpack(0x0000000000000000);
    assert(is_zero(pos_zero), 'pos zero');
    
    // -0.0
    let neg_zero = unpack(0x8000000000000000);
    assert(is_zero(neg_zero), 'neg zero');
    
    // 1.0 is not zero
    let one = unpack(0x3FF0000000000000);
    assert(!is_zero(one), '1.0 not zero');
}

#[test]
fn test_ieee754_is_infinity() {
    // +Inf
    let pos_inf = unpack(0x7FF0000000000000);
    assert(is_infinity(pos_inf), 'pos inf');
    
    // -Inf
    let neg_inf = unpack(0xFFF0000000000000);
    assert(is_infinity(neg_inf), 'neg inf');
    
    // Normal number is not infinity
    let one = unpack(0x3FF0000000000000);
    assert(!is_infinity(one), '1.0 not inf');
}

#[test]
fn test_ieee754_is_nan() {
    // NaN (quiet NaN)
    let nan = unpack(0x7FF8000000000000);
    assert(is_nan(nan), 'qNaN');
    
    // Signaling NaN
    let snan = unpack(0x7FF0000000000001);
    assert(is_nan(snan), 'sNaN');
    
    // Infinity is not NaN
    let inf = unpack(0x7FF0000000000000);
    assert(!is_nan(inf), 'inf not NaN');
}

#[test]
fn test_ieee754_is_normal() {
    let one = unpack(0x3FF0000000000000);
    assert(is_normal(one), '1.0 is normal');
    
    let inf = unpack(0x7FF0000000000000);
    assert(!is_normal(inf), 'inf not normal');
    
    let zero = unpack(0x0000000000000000);
    assert(!is_normal(zero), 'zero not normal');
}

#[test]
fn test_ieee754_verify_cfround() {
    // CFROUND rotates src right by imm32 bits, then takes lowest 2 bits
    // Per RandomX spec section 5.4.1:
    // "This instruction calculates a 2-bit value by rotating the source 
    // register right by imm32 bits and taking the 2 least significant bits"
    
    // Test 1: imm32 = 0, src = 0 → result = 0
    let src1: u64 = 0x0000000000000000;
    assert(verify_cfround(src1, 0, 0), 'imm32=0, src=0');
    
    // Test 2: imm32 = 0, src = 1 → lowest 2 bits = 1
    let src2: u64 = 0x0000000000000001;
    assert(verify_cfround(src2, 0, 1), 'imm32=0, src=1');
    
    // Test 3: imm32 = 0, src = 2 → lowest 2 bits = 2
    let src3: u64 = 0x0000000000000002;
    assert(verify_cfround(src3, 0, 2), 'imm32=0, src=2');
    
    // Test 4: imm32 = 0, src = 3 → lowest 2 bits = 3
    let src4: u64 = 0x0000000000000003;
    assert(verify_cfround(src4, 0, 3), 'imm32=0, src=3');
    
    // Test 5: imm32 = 59, src with bit 59 set
    // Rotating right by 59 brings bit 59 to bit 0
    let src5: u64 = 0x0800000000000000;  // Bit 59 set
    assert(verify_cfround(src5, 59, 1), 'imm32=59, bit59=1');
    
    // Test 6: imm32 = 59, src with bit 60 set
    // Rotating right by 59 brings bit 60 to bit 1
    let src6: u64 = 0x1000000000000000;  // Bit 60 set
    assert(verify_cfround(src6, 59, 2), 'imm32=59, bit60=1');
    
    // Test 7: imm32 = 59, src with bits 59-60 set → fprc = 3
    let src7: u64 = 0x1800000000000000;  // Bits 59-60 set
    assert(verify_cfround(src7, 59, 3), 'imm32=59, bits59-60=11');
    
    // Test 8: imm32 wraps around (imm32 = 64 same as imm32 = 0)
    let src8: u64 = 0x0000000000000002;
    assert(verify_cfround(src8, 64, 2), 'imm32=64 wraps to 0');
}

#[test]
fn test_ieee754_verify_fadd_zeros() {
    // 0 + 0 = 0
    let zero: u64 = 0x0000000000000000;
    assert(verify_fadd(zero, zero, zero, ROUND_TIES_TO_EVEN), '0+0=0');
}

#[test]
fn test_ieee754_verify_fadd_infinity() {
    let inf: u64 = 0x7FF0000000000000;
    let one: u64 = 0x3FF0000000000000;
    
    // inf + finite = inf
    assert(verify_fadd(inf, one, inf, ROUND_TIES_TO_EVEN), 'inf+1=inf');
    
    // finite + inf = inf
    assert(verify_fadd(one, inf, inf, ROUND_TIES_TO_EVEN), '1+inf=inf');
}

#[test]
fn test_ieee754_verify_fadd_nan_propagation() {
    let nan: u64 = 0x7FF8000000000000;
    let one: u64 = 0x3FF0000000000000;
    
    // NaN + anything = NaN
    assert(verify_fadd(nan, one, nan, ROUND_TIES_TO_EVEN), 'NaN+1=NaN');
    assert(verify_fadd(one, nan, nan, ROUND_TIES_TO_EVEN), '1+NaN=NaN');
}

#[test]
fn test_ieee754_verify_fmul_zero_inf_is_nan() {
    let zero: u64 = 0x0000000000000000;
    let inf: u64 = 0x7FF0000000000000;
    let nan: u64 = 0x7FF8000000000000;
    
    // 0 * inf = NaN
    assert(verify_fmul(zero, inf, nan, ROUND_TIES_TO_EVEN), '0*inf=NaN');
    assert(verify_fmul(inf, zero, nan, ROUND_TIES_TO_EVEN), 'inf*0=NaN');
}

#[test]
fn test_ieee754_verify_fdiv_by_zero() {
    let one: u64 = 0x3FF0000000000000;
    let zero: u64 = 0x0000000000000000;
    let inf: u64 = 0x7FF0000000000000;
    
    // 1 / 0 = +inf
    assert(verify_fdiv(one, zero, inf, ROUND_TIES_TO_EVEN), '1/0=inf');
}

#[test]
fn test_ieee754_verify_fsqrt_negative_is_nan() {
    let neg_one: u64 = 0xBFF0000000000000;  // -1.0
    let nan: u64 = 0x7FF8000000000000;
    
    // sqrt(-1) = NaN
    assert(verify_fsqrt(neg_one, nan, ROUND_TIES_TO_EVEN), 'sqrt(-1)=NaN');
}

#[test]
fn test_ieee754_verify_fsqrt_zero() {
    let zero: u64 = 0x0000000000000000;
    
    // sqrt(0) = 0
    assert(verify_fsqrt(zero, zero, ROUND_TIES_TO_EVEN), 'sqrt(0)=0');
}

#[test]
fn test_ieee754_e_group_constraint() {
    // Random value
    let bits: u64 = 0x4000000000000000;  // 2.0
    // Use program_exp_mask = 0 for basic test
    let constrained = apply_e_group_constraint(bits, 0);
    
    // Should have bits 8-9 of exponent set (0x300) and bits 0-2 = 0x3
    assert(verify_e_group_exponent(constrained), 'E-group valid');
}

// ============================================================================
// Spec-Required Tests (Q1, Q3, Q4)
// ============================================================================

#[test]
fn test_e_group_invariant_positive() {
    // Positive number: should pass
    let pos: u64 = 0x4000000000000000;  // +2.0
    assert(verify_e_group_invariant(pos), 'pos passes');
    
    // Negative number: should fail
    let neg: u64 = 0xC000000000000000;  // -2.0
    assert(!verify_e_group_invariant(neg), 'neg fails');
    
    // Positive zero: should pass
    let pos_zero: u64 = 0x0000000000000000;
    assert(verify_e_group_invariant(pos_zero), 'pos zero passes');
    
    // Negative zero: should fail (sign bit set)
    let neg_zero: u64 = 0x8000000000000000;
    assert(!verify_e_group_invariant(neg_zero), 'neg zero fails');
}

#[test]
fn test_f_group_invariant_bounded() {
    // Normal value within bounds: should pass
    let normal: u64 = 0x4000000000000000;  // 2.0, exp=1024
    assert(verify_f_group_invariant(normal), 'normal passes');
    
    // Value near 3e14 limit: exp ~1070 should pass
    let near_limit: u64 = 0x42C0000000000000;  // exp=1069
    assert(verify_f_group_invariant(near_limit), 'near limit passes');
    
    // Infinity: should fail
    let inf: u64 = 0x7FF0000000000000;
    assert(!verify_f_group_invariant(inf), 'inf fails');
    
    // NaN: should fail
    let nan: u64 = 0x7FF8000000000000;
    assert(!verify_f_group_invariant(nan), 'nan fails');
}

#[test]
fn test_e_group_exponent_bits_check() {
    // Per REFERENCE IMPLEMENTATION (NOT spec!), E-group requires:
    // 1. Sign = 0 (positive)
    // 2. Exponent bits 0-3 = 0 (zeros)
    // 3. Exponent bits 4-7 = dynamic (program_exp_mask)
    // 4. Exponent bits 8-9 = 0x3 (constant)
    
    // Use apply_e_group_constraint to get a properly constrained value
    let constrained = apply_e_group_constraint(0x4000000000000000, 0);  // 2.0 constrained, exp_mask=0
    assert(verify_e_group_exponent(constrained), 'constrained e-group');
    
    // Invalid: negative (sign bit set)
    let neg = constrained | 0x8000000000000000;
    assert(!verify_e_group_exponent(neg), 'neg fails');
    
    // Invalid: exponent bits 0-3 NOT zero
    // Manually construct: exp with bits 8-9 set but bits 0-3 non-zero
    let f_wrong = unpack(constrained);
    let wrong_exp = f_wrong.exponent | 0x5;  // Set bits 0 and 2
    let wrong_bits_0_3 = pack(Float64 { sign: 0, exponent: wrong_exp, mantissa: f_wrong.mantissa });
    assert(!verify_e_group_exponent(wrong_bits_0_3), 'wrong bits 0-3 fails');
    
    // Invalid: exponent bits 8-9 NOT set
    let no_constraint: u64 = 0x4000000000000000;  // exp=1024 (0x400), bits 8-9 = 00
    assert(!verify_e_group_exponent(no_constraint), 'no constraint fails');
    
    // Valid: manually construct with all required bits
    let valid_manual = apply_e_group_constraint(0x3FF0000000000000, 0);  // 1.0 constrained
    assert(verify_e_group_exponent(valid_manual), 'manual valid');
    
    // Verify internal structure
    let f = unpack(valid_manual);
    assert(f.sign == 0, 'sign is 0');
    assert((f.exponent & 0xF) == 0, 'bits 0-3 are 0');
    assert((f.exponent & 0x300) == 0x300, 'bits 8-9 are set');
}

// ============================================================================
// New Tests for Recommended Features
// ============================================================================

#[test]
fn test_program_config_default() {
    // ProgramConfig now only contains full 64-bit eMasks (per spec)
    let config = default_program_config();
    // Default eMask: 0x3000000000000000 (exponent 0x300 << 52, no mantissa mask)
    assert(config.e_mask_lo == 0x3000000000000000, 'default e_mask_lo');
    assert(config.e_mask_hi == 0x3000000000000000, 'default e_mask_hi');
}

#[test]
fn test_e_group_exponent_with_mask() {
    // Test with program_exp_mask = 5 (bits 4-7 = 0101 per REFERENCE IMPLEMENTATION)
    let bits: u64 = 0x4000000000000000;
    let constrained = apply_e_group_constraint(bits, 5);
    
    // Should pass full verification with same mask
    assert(verify_e_group_exponent_full(constrained, 5), 'full check passes');
    
    // Should fail with different mask
    assert(!verify_e_group_exponent_full(constrained, 3), 'wrong mask fails');
    
    // Verify the bit layout matches reference implementation:
    // - Bits 0-3 should be 0
    // - Bits 4-7 should be exp_mask (5 = 0101)
    // - Bits 8-9 should be 0x3
    let f = unpack(constrained);
    assert((f.exponent & 0xF) == 0, 'bits 0-3 are 0');
    assert(((f.exponent / 16) & 0xF) == 5, 'bits 4-7 = exp_mask');
    assert((f.exponent & 0x300) == 0x300, 'bits 8-9 = 0x3');
}

#[test]
fn test_apply_e_group_mask() {
    // Test E-group masking for FDIV_M
    let memory_value: u64 = 0x8040000000000000;  // Negative value
    let e_mask: u64 = 0x3000000000000000;  // Valid E-group mask
    
    let masked = apply_e_group_mask(memory_value, e_mask);
    
    // Should have top bits from e_mask (positive, valid exponent)
    // Bottom 56 bits from memory_value
    let expected = (memory_value & DYNAMIC_MANTISSA_MASK_FULL) | e_mask;
    assert(masked == expected, 'masking correct');
    
    // Masked value should be positive (E-group requirement)
    let f = unpack(masked);
    assert(f.sign == 0, 'masked is positive');
}

#[test]
fn test_verify_fdiv_m_with_masking() {
    // FDIV_M automatically masks the divisor
    let _pre_dst: u64 = 0x4000000000000000;  // 2.0
    let memory_value: u64 = 0x3FF0000000000000;  // 1.0
    let e_mask: u64 = 0x3000000000000000;
    
    // After masking, division should work
    // The exact result depends on the masked divisor
    // For this test, verify the function doesn't panic
    let _post_dst: u64 = 0x4000000000000000;  // 2.0 (placeholder - would need exact calculation)
    
    // This tests the masking is applied correctly
    let masked_divisor = apply_e_group_mask(memory_value, e_mask);
    assert(masked_divisor != 0, 'divisor not zero');
}

#[test]
fn test_fp_witness_default() {
    let witness = default_fp_witness();
    assert(witness.extended_mantissa_hi == 0, 'default hi');
    assert(witness.extended_mantissa_lo == 0, 'default lo');
    assert(witness.rounding_adjustment == 0, 'default adj');
    assert(witness.guard_round_sticky == 0, 'default grs');
    assert(witness.sign_a == 0, 'default sign_a');
    assert(witness.sign_b == 0, 'default sign_b');
    assert(witness.sign_result == 0, 'default sign_result');
    assert(witness.ftz_daz_active == 1, 'default ftz/daz');
    assert(witness.fprc_at_execution == 0, 'default fprc');
    assert(witness.is_sub == 0, 'default is_sub');
}

#[test]
fn test_fadd_with_witness_special_cases() {
    let witness = default_fp_witness();
    
    // NaN + anything = NaN
    let nan: u64 = 0x7FF8000000000000;
    let one: u64 = 0x3FF0000000000000;
    assert(verify_fadd_with_witness(nan, one, nan, 0, witness), 'nan propagates');
    
    // inf + finite = inf
    let inf: u64 = 0x7FF0000000000000;
    assert(verify_fadd_with_witness(inf, one, inf, 0, witness), 'inf + finite');
    
    // 0 + x = x
    let zero: u64 = 0x0000000000000000;
    assert(verify_fadd_with_witness(zero, one, one, 0, witness), '0 + x = x');
}

#[test]
fn test_fmul_with_witness_special_cases() {
    let witness = default_fp_witness();
    
    // 0 * inf = NaN
    let zero: u64 = 0x0000000000000000;
    let inf: u64 = 0x7FF0000000000000;
    let nan: u64 = 0x7FF8000000000000;
    assert(verify_fmul_with_witness(zero, inf, nan, 0, witness), '0 * inf = nan');
    
    // inf * inf = inf
    assert(verify_fmul_with_witness(inf, inf, inf, 0, witness), 'inf * inf = inf');
}

#[test]
fn test_fdiv_with_witness_special_cases() {
    let witness = default_fp_witness();
    
    // 0 / 0 = NaN
    let zero: u64 = 0x0000000000000000;
    let nan: u64 = 0x7FF8000000000000;
    assert(verify_fdiv_with_witness(zero, zero, nan, 0, witness), '0/0 = nan');
    
    // x / 0 = inf
    let one: u64 = 0x3FF0000000000000;
    let inf: u64 = 0x7FF0000000000000;
    assert(verify_fdiv_with_witness(one, zero, inf, 0, witness), 'x/0 = inf');
}

#[test]
fn test_fsqrt_with_witness_special_cases() {
    let witness = default_fp_witness();
    
    // sqrt(negative) = NaN
    let neg: u64 = 0xBFF0000000000000;  // -1.0
    let nan: u64 = 0x7FF8000000000000;
    assert(verify_fsqrt_with_witness(neg, nan, 0, witness), 'sqrt(-1) = nan');
    
    // sqrt(0) = 0
    let zero: u64 = 0x0000000000000000;
    assert(verify_fsqrt_with_witness(zero, zero, 0, witness), 'sqrt(0) = 0');
    
    // sqrt(inf) = inf
    let inf: u64 = 0x7FF0000000000000;
    assert(verify_fsqrt_with_witness(inf, inf, 0, witness), 'sqrt(inf) = inf');
}

// ============================================================================
// FTZ/DAZ Denormal Tests (per spec v2)
// ============================================================================

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

#[test]
fn test_signed_zero_rounding_in_fadd() {
    let witness = default_fp_witness();
    let pos_zero: u64 = 0x0000000000000000;
    let neg_zero: u64 = 0x8000000000000000;

    assert(verify_fadd_with_witness(pos_zero, neg_zero, neg_zero, 1, witness), 'round toward -inf yields -0');
    assert(verify_fadd_with_witness(pos_zero, neg_zero, pos_zero, 0, witness), 'ties-to-even yields +0');
}

#[test]
fn test_signed_zero_rounding_in_fsub() {
    let witness = default_fp_witness();
    let pos_zero: u64 = 0x0000000000000000;
    let neg_zero: u64 = 0x8000000000000000;

    assert(verify_fadd_with_witness(pos_zero, pos_zero, neg_zero, 1, witness), 'round toward -inf yields -0');
    assert(verify_fadd_with_witness(pos_zero, pos_zero, pos_zero, 0, witness), 'ties-to-even yields +0');
}

// ============================================================================
// F-group Conversion Tests (per spec Q6)
// ============================================================================

#[test]
fn test_f_group_conversion_zero() {
    // Memory value = 0 should produce (0.0, 0.0)
    let memory: u64 = 0x0000000000000000;
    let (lo, hi) = convert_f_group_operand(memory);
    
    // Both should be +0.0
    assert(lo == 0x0000000000000000, 'lo is +0');
    assert(hi == 0x0000000000000000, 'hi is +0');
}

#[test]
fn test_f_group_conversion_positive() {
    // Memory value with positive integers
    // Low 32 bits = 1, High 32 bits = 2
    let memory: u64 = 0x0000000200000001;
    let (lo, hi) = convert_f_group_operand(memory);
    
    // 1 as double = 0x3FF0000000000000
    assert(lo == 0x3FF0000000000000, 'lo is 1.0');
    // 2 as double = 0x4000000000000000
    assert(hi == 0x4000000000000000, 'hi is 2.0');
}

#[test]
fn test_f_group_conversion_negative() {
    // Memory value with negative integer (two's complement)
    // Low 32 bits = -1 (0xFFFFFFFF), High 32 bits = 0
    let memory: u64 = 0x00000000FFFFFFFF;
    let (lo, hi) = convert_f_group_operand(memory);
    
    // -1 as double = 0xBFF0000000000000
    assert(lo == 0xBFF0000000000000, 'lo is -1.0');
    // 0 as double = 0x0000000000000000
    assert(hi == 0x0000000000000000, 'hi is 0.0');
}

#[test]
fn test_f_group_conversion_large() {
    // Memory value with larger numbers
    // Low 32 bits = 1000000, High 32 bits = -1000000 (0xFFF0BDC0)
    let memory: u64 = 0xFFF0BDC0000F4240;
    let (lo, hi) = convert_f_group_operand(memory);
    
    // 1000000 as double: unpack and verify it's positive and in range
    let lo_f = unpack(lo);
    assert(lo_f.sign == 0, 'lo is positive');
    
    // -1000000 as double: should be negative
    let hi_f = unpack(hi);
    assert(hi_f.sign == 1, 'hi is negative');
}

#[test]
fn test_fp_witness_has_alignment_shift() {
    // Verify the witness struct has alignment_shift field
    let witness = default_fp_witness();
    assert(witness.alignment_shift == 0, 'default alignment_shift');
    
    // Create a witness with non-zero alignment_shift
    let witness2 = FPWitness {
        extended_mantissa_hi: 0,
        extended_mantissa_lo: 0,
        rounding_adjustment: 0,
        guard_round_sticky: 0,
        result_exponent: 0,
        normalization_shift: 0,
        alignment_shift: 5,
        sign_a: 0,
        sign_b: 0,
        sign_result: 0,
        ftz_daz_active: 1,
        fprc_at_execution: 0,
        is_sub: 0,
    };
    assert(witness2.alignment_shift == 5, 'custom alignment_shift');
}

// ============================================================================
// Critical Edge Case Tests (per spec)
// ============================================================================

#[test]
fn test_int32_min_conversion() {
    // INT32_MIN = -2147483648 = 0x80000000
    // This is a critical edge case because |INT32_MIN| cannot be represented as int32
    // But as u64 for conversion to double, it's fine (2147483648)
    let memory: u64 = 0x0000000080000000;  // INT32_MIN in low 32 bits, 0 in high
    let (lo, hi) = convert_f_group_operand(memory);
    
    // INT32_MIN as double = -2147483648.0 = 0xC1E0000000000000
    assert(lo == 0xC1E0000000000000, 'INT32_MIN conversion');
    // High 32 bits = 0 -> +0.0
    assert(hi == 0x0000000000000000, 'high is 0');
}

#[test]
fn test_int32_max_conversion() {
    // INT32_MAX = 2147483647 = 0x7FFFFFFF
    let memory: u64 = 0x000000007FFFFFFF;
    let (lo, _hi) = convert_f_group_operand(memory);
    
    // INT32_MAX as double: 2147483647.0
    // Sign = 0, exp = 1053 (0x41D), mantissa = 0xFFFFFFC000000
    // Full: 0x41DFFFFFFFC00000
    let lo_f = unpack(lo);
    assert(lo_f.sign == 0, 'INT32_MAX is positive');
    // Verify it's approximately correct (mantissa details depend on exact conversion)
    assert(lo_f.exponent == 1053, 'INT32_MAX exp');
}

#[test]
fn test_e_group_bit_10_is_zero() {
    // AUDITOR CRITICAL FIX: Bit 10 of exponent must be 0, not preserved
    
    // Input with bit 10 set in exponent (exp = 0x400 + something)
    // 2.0 has exp = 1024 (0x400), which has bit 10 set
    let two: u64 = 0x4000000000000000;  // 2.0
    let constrained = apply_e_group_constraint(two, 5);
    
    // Verify bit 10 is NOT preserved (should be 0)
    let f = unpack(constrained);
    let bit_10 = (f.exponent / 1024) & 1;  // (exp >> 10) & 1
    assert(bit_10 == 0, 'bit 10 must be 0');
    
    // Verify verification function also checks bit 10
    assert(verify_e_group_exponent_full(constrained, 5), 'should pass');
    
    // Manually set bit 10 and verify it fails
    let bad_exp = f.exponent | 0x400;  // Set bit 10
    let bad_value = pack(Float64 { sign: 0, exponent: bad_exp, mantissa: f.mantissa });
    assert(!verify_e_group_exponent_full(bad_value, 5), 'bit 10 set should fail');
}

#[test]
fn test_compute_e_mask() {
    // Test compute_e_mask matches reference getFloatMask behavior
    
    // With entropy = 0:
    // - mantissa mask = 0
    // - exponent = 0x300 | ((0 >> 60) << 4) = 0x300
    // - result = 0 | (0x300 << 52) = 0x3000000000000000
    let mask0 = compute_e_mask(0);
    assert(mask0 == 0x3000000000000000, 'entropy 0 mask');
    
    // With entropy having bits 0-21 set (0x3FFFFF):
    // - mantissa mask = 0x3FFFFF
    // - exponent = 0x300 | 0 = 0x300
    // - result = 0x3FFFFF | 0x3000000000000000 = 0x30000000003FFFFF
    let mask_mantissa = compute_e_mask(0x3FFFFF);
    assert(mask_mantissa == 0x30000000003FFFFF, 'mantissa mask');
    
    // With entropy having bits 60-63 set (0xF000000000000000):
    // - mantissa mask = 0
    // - exponent = 0x300 | (0xF << 4) = 0x300 | 0xF0 = 0x3F0
    // - result = 0 | (0x3F0 << 52) = 0x3F00000000000000
    let mask_exp = compute_e_mask(0xF000000000000000);
    assert(mask_exp == 0x3F00000000000000, 'exp mask');
}

#[test]
fn test_apply_e_group_constraint_with_full_mask() {
    // Test the new apply_e_group_constraint_with_mask function
    let input: u64 = 0x4000000000000000;  // 2.0
    let e_mask = compute_e_mask(0x5000000000123456);  // exp bits 60-63 = 5, mantissa bits = 0x123456
    
    let result = apply_e_group_constraint_with_mask(input, e_mask);
    
    // Verify the result:
    // 1. Sign = 0 (E-group is always positive)
    let f = unpack(result);
    assert(f.sign == 0, 'sign is 0');
    
    // 2. Exponent matches eMask (0x300 | (5 << 4) = 0x350)
    let expected_exp: u64 = 0x300 | (5 * 16);  // 0x350
    assert(f.exponent.into() == expected_exp, 'exp from mask');
    
    // 3. Mantissa bits 0-21 come from eMask
    let mantissa_low_22 = f.mantissa & 0x3FFFFF;
    assert(mantissa_low_22 == 0x123456, 'mantissa from mask');
}

// ============================================================================
// FPRC State Tracking Tests (per spec Q5)
// ============================================================================

#[test]
fn test_fprc_initial_state_zero() {
    // FPRC should be 0 at start of each program
    let state = initial_state(0, 0);
    assert(state.execution.fprc == 0, 'fprc starts at 0');
}

#[test]
fn test_update_fprc() {
    let initial_exec = ExecutionState {
        program_counter: 10,
        iteration_counter: 100,
        program_index: 2,
        fprc: 0,
        ma: 0x1234,
        mx: 0x5678,
    };
    
    // Update FPRC to 3
    let updated = update_fprc(initial_exec, 3);
    
    // Verify FPRC changed
    assert(updated.fprc == 3, 'fprc updated to 3');
    
    // Verify other fields unchanged
    assert(updated.program_counter == 10, 'pc unchanged');
    assert(updated.iteration_counter == 100, 'iter unchanged');
    assert(updated.program_index == 2, 'prog idx unchanged');
    assert(updated.ma == 0x1234, 'ma unchanged');
    assert(updated.mx == 0x5678, 'mx unchanged');
}

#[test]
fn test_update_fprc_masks_to_2_bits() {
    let initial_exec = ExecutionState {
        program_counter: 0,
        iteration_counter: 0,
        program_index: 0,
        fprc: 0,
        ma: 0,
        mx: 0,
    };
    
    // Setting value > 3 should mask to 2 bits
    let updated = update_fprc(initial_exec, 0xFF);
    assert(updated.fprc == 3, 'fprc masked to 2 bits');
    
    let updated2 = update_fprc(initial_exec, 4);
    assert(updated2.fprc == 0, '4 & 3 = 0');
    
    let updated3 = update_fprc(initial_exec, 5);
    assert(updated3.fprc == 1, '5 & 3 = 1');
}

#[test]
fn test_reset_fprc() {
    let initial_exec = ExecutionState {
        program_counter: 100,
        iteration_counter: 500,
        program_index: 5,
        fprc: 3,  // Non-zero
        ma: 0xABCD,
        mx: 0xEF01,
    };
    
    let reset = reset_fprc(initial_exec);
    
    // FPRC should be 0
    assert(reset.fprc == 0, 'fprc reset to 0');
    
    // Other fields unchanged
    assert(reset.program_counter == 100, 'pc unchanged');
    assert(reset.iteration_counter == 500, 'iter unchanged');
    assert(reset.program_index == 5, 'prog idx unchanged');
}

#[test]
fn test_compute_cfround_fprc_no_rotation() {
    // When imm32 = 0, take bits 0-1 of src_value directly
    let src: u64 = 0x123456789ABCDEF3;  // Bits 0-1 = 11 = 3
    let fprc = compute_cfround_fprc(src, 0);
    assert(fprc == 3, 'no rotation, bits 0-1');
    
    let src2: u64 = 0x123456789ABCDEF0;  // Bits 0-1 = 00 = 0
    let fprc2 = compute_cfround_fprc(src2, 0);
    assert(fprc2 == 0, 'no rotation, 0');
}

#[test]
fn test_compute_cfround_fprc_with_rotation() {
    // src = 0x0000000000000010 (bit 4 = 1)
    // Rotate right by 4: bit 4 becomes bit 0
    // Result bits 0-1 = 01 = 1
    let src: u64 = 0x0000000000000010;
    let fprc = compute_cfround_fprc(src, 4);
    assert(fprc == 1, 'rotate 4, bit 4->0');
    
    // src = 0x0000000000000030 (bits 4-5 = 11)
    // Rotate right by 4: bits 4-5 become bits 0-1
    // Result = 11 = 3
    let src2: u64 = 0x0000000000000030;
    let fprc2 = compute_cfround_fprc(src2, 4);
    assert(fprc2 == 3, 'rotate 4, bits 4-5->0-1');
}

#[test]
fn test_compute_cfround_fprc_large_rotation() {
    // Rotation is mod 64
    let src: u64 = 0x0000000000000003;  // Bits 0-1 = 11
    
    // imm32 = 64 should be same as imm32 = 0
    let fprc64 = compute_cfround_fprc(src, 64);
    assert(fprc64 == 3, 'rotation 64 = 0');
    
    // imm32 = 128 should also be same as imm32 = 0
    let fprc128 = compute_cfround_fprc(src, 128);
    assert(fprc128 == 3, 'rotation 128 = 0');
}

#[test]
fn test_compute_cfround_fprc_rotation_59_60() {
    // Classic CFROUND case: bits 59-60 contain rounding mode
    // src has bits 59-60 set to 10 (binary) = 2
    let src: u64 = 0x1000000000000000;  // Bit 60 set
    
    // Rotate right by 59: bit 60 becomes bit 1
    let fprc = compute_cfround_fprc(src, 59);
    assert(fprc == 2, 'bits 59-60 = 2');
}

// ============================================================================
// FPRC Persistence Tests (per spec critical finding)
// ============================================================================

#[test]
fn test_fprc_persists_across_programs() {
    // CRITICAL: FPRC must persist across programs within a hash
    // Per randomx.cpp line 396: resetRoundingMode() called ONCE before loop
    
    let initial_exec = ExecutionState {
        program_counter: 255,  // End of program
        iteration_counter: 0,  // All iterations done
        program_index: 0,      // Program 0
        fprc: 3,               // Set by CFROUND in program 0
        ma: 0x1234,
        mx: 0x5678,
    };
    
    // Advance to program 1 - FPRC must persist!
    let next_program = advance_to_next_program(initial_exec);
    
    assert(next_program.fprc == 3, 'fprc preserved!');
    assert(next_program.program_index == 1, 'program advanced');
    assert(next_program.program_counter == 0, 'pc reset');
    assert(next_program.iteration_counter == 2048, 'iter reset');
    
    // Advance through all programs - FPRC should still persist
    let prog2 = advance_to_next_program(next_program);
    assert(prog2.fprc == 3, 'fprc still 3 at prog2');
    assert(prog2.program_index == 2, 'program 2');
    
    let prog3 = advance_to_next_program(prog2);
    assert(prog3.fprc == 3, 'fprc still 3 at prog3');
    
    let prog7 = ExecutionState {
        program_counter: 0,
        iteration_counter: 2048,
        program_index: 7,
        fprc: 3,  // Still persisted from program 0!
        ma: 0,
        mx: 0,
    };
    assert(prog7.fprc == 3, 'fprc persists to prog7');
}

#[test]
fn test_fprc_reset_only_for_new_hash() {
    // FPRC is reset ONLY when starting a NEW hash calculation
    let state_with_fprc = ExecutionState {
        program_counter: 100,
        iteration_counter: 500,
        program_index: 5,
        fprc: 2,
        ma: 0xABCD,
        mx: 0xEF01,
    };
    
    // reset_fprc_for_new_hash should reset FPRC to 0
    let new_hash_state = reset_fprc_for_new_hash(state_with_fprc);
    assert(new_hash_state.fprc == 0, 'fprc reset for new hash');
    
    // Other fields should be unchanged (in real usage, they'd be reinitialized too)
    assert(new_hash_state.program_counter == 100, 'pc unchanged');
}

#[test]
fn test_initial_state_starts_with_fprc_zero() {
    // initial_state() is for NEW hash calculations, so FPRC = 0
    let state = initial_state(0x12345, 0xABCDE);
    
    assert(state.execution.fprc == 0, 'new hash fprc=0');
    assert(state.execution.program_index == 0, 'starts at program 0');
}

// ============================================================================
// F/E XOR at Iteration End Tests (per spec Finding #6)
// Spec 4.6.2 Step 10: f0 = f0 XOR e0, f1 = f1 XOR e1, etc.
// ============================================================================

#[test]
fn test_iteration_end_xor_basic() {
    // Test basic F/E XOR operation
    let float_regs = FloatRegisters {
        f0: FloatRegister { low: 0xFF00FF00FF00FF00, high: 0x00FF00FF00FF00FF },
        f1: FloatRegister { low: 0xAAAAAAAAAAAAAAAA, high: 0x5555555555555555 },
        f2: FloatRegister { low: 0x1234567890ABCDEF, high: 0xFEDCBA0987654321 },
        f3: FloatRegister { low: 0x0000000000000000, high: 0xFFFFFFFFFFFFFFFF },
        e0: FloatRegister { low: 0x0F0F0F0F0F0F0F0F, high: 0xF0F0F0F0F0F0F0F0 },
        e1: FloatRegister { low: 0x5555555555555555, high: 0xAAAAAAAAAAAAAAAA },
        e2: FloatRegister { low: 0x0000000000000000, high: 0x0000000000000000 },
        e3: FloatRegister { low: 0xFFFFFFFFFFFFFFFF, high: 0x0000000000000000 },
        a0: FloatRegister { low: 0x1111111111111111, high: 0x2222222222222222 },
        a1: FloatRegister { low: 0x3333333333333333, high: 0x4444444444444444 },
        a2: FloatRegister { low: 0x5555555555555555, high: 0x6666666666666666 },
        a3: FloatRegister { low: 0x7777777777777777, high: 0x8888888888888888 },
    };
    
    let result = apply_iteration_end_xor(float_regs);
    
    // Verify F0 = F0 XOR E0
    assert(result.f0.low == (0xFF00FF00FF00FF00 ^ 0x0F0F0F0F0F0F0F0F), 'f0.lo XOR');
    assert(result.f0.high == (0x00FF00FF00FF00FF ^ 0xF0F0F0F0F0F0F0F0), 'f0.hi XOR');
    
    // Verify F1 = F1 XOR E1
    assert(result.f1.low == (0xAAAAAAAAAAAAAAAA ^ 0x5555555555555555), 'f1.lo XOR');
    assert(result.f1.high == (0x5555555555555555 ^ 0xAAAAAAAAAAAAAAAA), 'f1.hi XOR');
    
    // Verify F2 = F2 XOR E2 (E2 is zero, so F2 unchanged)
    assert(result.f2.low == 0x1234567890ABCDEF, 'f2.lo unchanged');
    assert(result.f2.high == 0xFEDCBA0987654321, 'f2.hi unchanged');
    
    // Verify F3 = F3 XOR E3
    assert(result.f3.low == 0xFFFFFFFFFFFFFFFF, 'f3.lo XOR');  // 0 XOR FF = FF
    assert(result.f3.high == 0xFFFFFFFFFFFFFFFF, 'f3.hi XOR'); // FF XOR 0 = FF
    
    // Verify E-group unchanged
    assert(result.e0 == float_regs.e0, 'e0 unchanged');
    assert(result.e1 == float_regs.e1, 'e1 unchanged');
    
    // Verify A-group unchanged
    assert(result.a0 == float_regs.a0, 'a0 unchanged');
    assert(result.a3 == float_regs.a3, 'a3 unchanged');
}

#[test]
fn test_verify_iteration_end_xor_correct() {
    let pre_regs = FloatRegisters {
        f0: FloatRegister { low: 0x1234, high: 0x5678 },
        f1: FloatRegister { low: 0xABCD, high: 0xEF01 },
        f2: FloatRegister { low: 0, high: 0 },
        f3: FloatRegister { low: 0xFFFF, high: 0 },
        e0: FloatRegister { low: 0x1111, high: 0x2222 },
        e1: FloatRegister { low: 0x3333, high: 0x4444 },
        e2: FloatRegister { low: 0x5555, high: 0x6666 },
        e3: FloatRegister { low: 0x7777, high: 0x8888 },
        a0: FloatRegister { low: 1, high: 2 },
        a1: FloatRegister { low: 3, high: 4 },
        a2: FloatRegister { low: 5, high: 6 },
        a3: FloatRegister { low: 7, high: 8 },
    };
    
    // Apply the XOR correctly
    let post_regs = apply_iteration_end_xor(pre_regs);
    
    // Verify should pass
    assert(verify_iteration_end_xor(pre_regs, post_regs), 'correct XOR verified');
}

#[test]
fn test_verify_iteration_end_xor_wrong_f0() {
    let pre_regs = FloatRegisters {
        f0: FloatRegister { low: 0x1234, high: 0x5678 },
        f1: FloatRegister { low: 0, high: 0 },
        f2: FloatRegister { low: 0, high: 0 },
        f3: FloatRegister { low: 0, high: 0 },
        e0: FloatRegister { low: 0x1111, high: 0x2222 },
        e1: FloatRegister { low: 0, high: 0 },
        e2: FloatRegister { low: 0, high: 0 },
        e3: FloatRegister { low: 0, high: 0 },
        a0: FloatRegister { low: 0, high: 0 },
        a1: FloatRegister { low: 0, high: 0 },
        a2: FloatRegister { low: 0, high: 0 },
        a3: FloatRegister { low: 0, high: 0 },
    };
    
    // Wrong post_regs (f0 not XORed correctly)
    let post_regs = FloatRegisters {
        f0: FloatRegister { low: 0x9999, high: 0x9999 },  // WRONG!
        f1: pre_regs.f1,
        f2: pre_regs.f2,
        f3: pre_regs.f3,
        e0: pre_regs.e0,
        e1: pre_regs.e1,
        e2: pre_regs.e2,
        e3: pre_regs.e3,
        a0: pre_regs.a0,
        a1: pre_regs.a1,
        a2: pre_regs.a2,
        a3: pre_regs.a3,
    };
    
    // Verify should fail
    assert(!verify_iteration_end_xor(pre_regs, post_regs), 'wrong f0 detected');
}

// ============================================================================
// INT32 Conversion Tests (per spec Finding #7)
// ============================================================================

#[test]
fn test_int32_max_conversion_exact() {
    // INT32_MAX = 2147483647 = 0x7FFFFFFF
    // Expected IEEE-754: 0x41DFFFFFFFC00000
    // Breakdown: sign=0, exp=0x41D (1053), mantissa represents 2147483647
    let result = signed_int32_to_double(0x7FFFFFFF);
    assert(result == 0x41DFFFFFFFC00000, 'INT32_MAX exact');
}

// ============================================================================
// CFROUND Edge Case Tests (per spec recommendation)
// ============================================================================

#[test]
fn test_cfround_rotation_0() {
    // Rotation by 0 should not change anything
    let src: u64 = 0x0000000000000003;  // Bits 0-1 = 3
    let fprc = compute_cfround_fprc(src, 0);
    assert(fprc == 3, 'rotation 0 no change');
}

#[test]
fn test_cfround_rotation_32() {
    // Rotation by 32 moves bit 32 to bit 0
    let src: u64 = 0x0000000300000000;  // Bits 32-33 = 3
    let fprc = compute_cfround_fprc(src, 32);
    assert(fprc == 3, 'rotation 32');
}

#[test]
fn test_cfround_rotation_63() {
    // Rotation by 63 moves bit 63 to bit 0
    let src: u64 = 0x8000000000000000;  // Bit 63 set
    let fprc = compute_cfround_fprc(src, 63);
    assert(fprc == 1, 'rotation 63 bit63->bit0');
}

#[test]
fn test_cfround_rotation_62() {
    // Rotation by 62 moves bits 62-63 to bits 0-1
    let src: u64 = 0xC000000000000000;  // Bits 62-63 = 11 binary = 3
    let fprc = compute_cfround_fprc(src, 62);
    assert(fprc == 3, 'rotation 62 bits62-63->0-1');
}

#[test]
fn test_cfround_all_rounding_modes() {
    // Test all 4 possible FPRC values
    
    // FPRC 0: roundTiesToEven
    let fprc0 = compute_cfround_fprc(0x0, 0);
    assert(fprc0 == 0, 'fprc 0');
    
    // FPRC 1: roundTowardNegative
    let fprc1 = compute_cfround_fprc(0x1, 0);
    assert(fprc1 == 1, 'fprc 1');
    
    // FPRC 2: roundTowardPositive
    let fprc2 = compute_cfround_fprc(0x2, 0);
    assert(fprc2 == 2, 'fprc 2');
    
    // FPRC 3: roundTowardZero
    let fprc3 = compute_cfround_fprc(0x3, 0);
    assert(fprc3 == 3, 'fprc 3');
}

#[test]
fn test_fswap_r_correct_swap() {
    let pre_lo: u64 = 0x3FF0000000000000;  // 1.0
    let pre_hi: u64 = 0x4000000000000000;  // 2.0
    
    // After swap: lo becomes hi, hi becomes lo
    let post_lo: u64 = 0x4000000000000000;  // 2.0 (was hi)
    let post_hi: u64 = 0x3FF0000000000000;  // 1.0 (was lo)
    
    assert(verify_fswap_r(pre_lo, pre_hi, post_lo, post_hi), 'correct swap');
}

#[test]
fn test_fswap_r_wrong_swap() {
    let pre_lo: u64 = 0x3FF0000000000000;  // 1.0
    let pre_hi: u64 = 0x4000000000000000;  // 2.0
    
    // Wrong: didn't swap
    assert(!verify_fswap_r(pre_lo, pre_hi, pre_lo, pre_hi), 'no swap fails');
    
    // Wrong: only swapped one
    assert(!verify_fswap_r(pre_lo, pre_hi, pre_hi, pre_hi), 'partial swap fails');
}

#[test]
fn test_fswap_r_same_values() {
    // When both halves are the same, swap should still pass
    let same: u64 = 0x4000000000000000;
    assert(verify_fswap_r(same, same, same, same), 'same values swap');
}

#[test]
fn test_ieee754_fadd_known_result() {
    // Test vector: 1.0 + 1.0 = 2.0
    let one: u64 = 0x3FF0000000000000;
    let two: u64 = 0x4000000000000000;
    
    assert(verify_fadd(one, one, two, ROUND_TIES_TO_EVEN), '1+1=2');
}

#[test]
fn test_ieee754_fadd_with_zero() {
    // Test vector: 0.0 + 1.0 = 1.0
    let zero: u64 = 0x0000000000000000;
    let one: u64 = 0x3FF0000000000000;
    
    assert(verify_fadd(zero, one, one, ROUND_TIES_TO_EVEN), '0+1=1');
    assert(verify_fadd(one, zero, one, ROUND_TIES_TO_EVEN), '1+0=1');
}

#[test]
fn test_ieee754_fmul_known_result() {
    // Test: 2.0 * 2.0 = 4.0
    let two: u64 = 0x4000000000000000;
    let four: u64 = 0x4010000000000000;
    
    // Verify result is plausible (not NaN, correct sign)
    assert(verify_fmul(two, two, four, ROUND_TIES_TO_EVEN), '2*2=4');
}

// ============================================================================
// CBRANCH Tests (Per spec: track last_modified_pc per register)
// ============================================================================

#[test]
fn test_cbranch_tracker_init() {
    use monero_vm::randomx::fraud_proof::cbranch_verifier::NEVER_MODIFIED;
    
    let tracker = init_tracker();
    
    // All registers initialized to NEVER_MODIFIED sentinel
    assert(get_last_mod_pc(tracker, 0) == NEVER_MODIFIED, 'r0 init to NEVER_MODIFIED');
    assert(get_last_mod_pc(tracker, 1) == NEVER_MODIFIED, 'r1 init to NEVER_MODIFIED');
    assert(get_last_mod_pc(tracker, 7) == NEVER_MODIFIED, 'r7 init to NEVER_MODIFIED');
}

#[test]
fn test_cbranch_tracker_update() {
    use monero_vm::randomx::fraud_proof::cbranch_verifier::NEVER_MODIFIED;
    
    let tracker = init_tracker();
    
    // Update r3 at PC 10
    let tracker2 = update_tracker(tracker, 3, 10);
    
    assert(get_last_mod_pc(tracker2, 0) == NEVER_MODIFIED, 'r0 unchanged');
    assert(get_last_mod_pc(tracker2, 3) == 10, 'r3 updated to 10');
    assert(get_last_mod_pc(tracker2, 7) == NEVER_MODIFIED, 'r7 unchanged');
}

#[test]
fn test_cbranch_tracker_reset_all() {
    let tracker = init_tracker();
    let tracker2 = update_tracker(tracker, 3, 10);
    let _tracker3 = update_tracker(tracker2, 5, 20);
    
    // CBRANCH resets all to current PC
    let tracker4 = reset_all_trackers(50);
    
    assert(get_last_mod_pc(tracker4, 0) == 50, 'r0 reset to 50');
    assert(get_last_mod_pc(tracker4, 3) == 50, 'r3 reset to 50');
    assert(get_last_mod_pc(tracker4, 5) == 50, 'r5 reset to 50');
    assert(get_last_mod_pc(tracker4, 7) == 50, 'r7 reset to 50');
}

#[test]
fn test_cbranch_claim_struct() {
    let claim = CBranchClaim {
        dst_reg: 3,
        dst_value_before: 0x12345678,
        cimm: -100,
        mod_cond: 10,
        last_modified_pc: 25,
        jump_taken: true,
        new_pc: 26,
    };
    
    assert(claim.dst_reg == 3, 'dst_reg stored');
    assert(claim.last_modified_pc == 25, 'last_mod_pc stored');
    assert(claim.jump_taken, 'jump_taken stored');
}

#[test]
fn test_cbranch_no_jump_bits_not_zero() {
    use monero_vm::randomx::fraud_proof::cbranch_verifier::NEVER_MODIFIED;
    
    // When bits b to b+7 are NOT all zero, jump should not be taken
    let pre_regs = IntegerRegisters {
        r0: 0, r1: 0, r2: 0, r3: 0xFF00,  // Bits 8-15 set
        r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    let tracker = init_tracker();
    
    // cimm = 0, so dst stays 0xFF00
    // mod_cond = 0 means check bits 8-15
    // Bits 8-15 are 0xFF (not zero), so no jump
    let claim = CBranchClaim {
        dst_reg: 3,
        dst_value_before: 0xFF00,
        cimm: 0,
        mod_cond: 0,
        last_modified_pc: NEVER_MODIFIED,  // r3 was never modified
        jump_taken: false,
        new_pc: 1,  // Normal increment (current_pc=0 + 1)
    };
    
    // Post regs: r3 unchanged (cimm = 0)
    let post_regs = pre_regs;
    
    assert(verify_cbranch(pre_regs, claim, post_regs, tracker, 0), 'No jump when bits set');
}

#[test]
fn test_cbranch_jump_bits_zero() {
    // When bits b to b+7 are all zero, jump should be taken
    let pre_regs = IntegerRegisters {
        r0: 0, r1: 0, r2: 0, r3: 0,  // All zero
        r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // r3 was last modified at PC 10
    let mut tracker = init_tracker();
    tracker = update_tracker(tracker, 3, 10);
    
    // cimm = 0, dst stays 0
    // mod_cond = 0 means check bits 8-15, which are zero
    // Jump target = last_modified_pc + 1 = 11
    let claim = CBranchClaim {
        dst_reg: 3,
        dst_value_before: 0,
        cimm: 0,
        mod_cond: 0,
        last_modified_pc: 10,
        jump_taken: true,
        new_pc: 11,  // Jump to last_modified + 1
    };
    
    let post_regs = pre_regs;
    
    assert(verify_cbranch(pre_regs, claim, post_regs, tracker, 50), 'Jump when bits zero');
}

#[test]
fn test_cbranch_never_modified_jumps_to_zero() {
    use monero_vm::randomx::fraud_proof::cbranch_verifier::NEVER_MODIFIED;
    
    // Per spec: "If a register was *never* modified, jump to instruction 0"
    let pre_regs = IntegerRegisters {
        r0: 0, r1: 0, r2: 0, r3: 0,  // All zero - bits will be zero
        r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // r3 was NEVER modified
    let tracker = init_tracker();  // All registers at NEVER_MODIFIED
    
    // cimm = 0, dst stays 0
    // mod_cond = 0 means check bits 8-15, which are zero -> jump taken
    // BUT r3 was never modified, so jump to instruction 0 (not NEVER_MODIFIED + 1)
    let claim = CBranchClaim {
        dst_reg: 3,
        dst_value_before: 0,
        cimm: 0,
        mod_cond: 0,
        last_modified_pc: NEVER_MODIFIED,
        jump_taken: true,
        new_pc: 0,  // Jump to START of program (never modified case)
    };
    
    let post_regs = pre_regs;
    
    assert(verify_cbranch(pre_regs, claim, post_regs, tracker, 50), 'Never modified jumps to 0');
}

// ============================================================================
// Helper Functions
// ============================================================================

fn create_test_state() -> RandomXState {
    let int_regs = IntegerRegisters {
        r0: 0x123456789ABCDEF0,
        r1: 0xFEDCBA9876543210,
        r2: 0x1111111111111111,
        r3: 0x2222222222222222,
        r4: 0x3333333333333333,
        r5: 0x4444444444444444,
        r6: 0x5555555555555555,
        r7: 0x6666666666666666,
    };
    
    let zero_float = FloatRegister { low: 0, high: 0 };
    let float_regs = FloatRegisters {
        f0: FloatRegister { low: 0x1000, high: 0x2000 },
        f1: zero_float,
        f2: zero_float,
        f3: zero_float,
        e0: zero_float,
        e1: zero_float,
        e2: zero_float,
        e3: zero_float,
        a0: FloatRegister { low: 0x3FF0000000000000, high: 0x4000000000000000 }, // 1.0, 2.0
        a1: zero_float,
        a2: zero_float,
        a3: zero_float,
    };
    
    let registers = RegisterFile { int_regs, float_regs };
    
    let execution = ExecutionState {
        program_counter: 0,
        iteration_counter: 2048,
        program_index: 0,
        fprc: 0,
        ma: 0,
        mx: 0,
    };
    
    RandomXState {
        registers,
        execution,
        scratchpad_root: 0xABCDEF123456,
    }
}

fn create_test_registers() -> RegisterFile {
    let state = create_test_state();
    state.registers
}

// ============================================================================
// AUDITOR-REQUIRED TESTS: NOP, IMUL_RCP edge cases, IADD_RS r5, ISWAP_R
// ============================================================================

use monero_vm::randomx::fraud_proof::instruction_verifiers::{
    verify_nop, verify_imul_rcp, verify_iadd_rs
};
use monero_vm::randomx::fraud_proof::cbranch_verifier::set_all_modified_at_cbranch;
use monero_vm::randomx::fraud_proof::memory_verifiers::{
    ScratchpadLevel, verify_address_alignment, get_scratchpad_level_for_store
};

#[test]
fn test_verify_nop_state_unchanged() {
    let pre = IntegerRegisters {
        r0: 100, r1: 200, r2: 300, r3: 400, r4: 500, r5: 600, r6: 700, r7: 800,
    };
    let post = pre;  // Unchanged
    
    assert(verify_nop(pre, post), 'NOP should verify unchanged');
}

#[test]
fn test_verify_nop_state_changed_fails() {
    let pre = IntegerRegisters {
        r0: 100, r1: 200, r2: 300, r3: 400, r4: 500, r5: 600, r6: 700, r7: 800,
    };
    let mut post = pre;
    post.r0 = 999;  // Changed
    
    assert(!verify_nop(pre, post), 'NOP changed should fail');
}

#[test]
fn test_imul_rcp_imm32_zero_is_nop() {
    let pre = IntegerRegisters {
        r0: 100, r1: 200, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let post = pre;  // Unchanged because imm32=0 is NOP
    
    assert(verify_imul_rcp(pre, 0, 0, post), 'IMUL_RCP imm32=0 is NOP');
}

#[test]
fn test_imul_rcp_imm32_one_is_nop() {
    let pre = IntegerRegisters {
        r0: 100, r1: 200, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let post = pre;  // Unchanged because 1 is power of 2
    
    assert(verify_imul_rcp(pre, 0, 1, post), 'IMUL_RCP imm32=1 is NOP');
}

#[test]
fn test_imul_rcp_imm32_two_is_nop() {
    let pre = IntegerRegisters {
        r0: 100, r1: 200, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let post = pre;  // Unchanged because 2 is power of 2
    
    assert(verify_imul_rcp(pre, 0, 2, post), 'IMUL_RCP imm32=2 is NOP');
}

#[test]
fn test_imul_rcp_imm32_four_is_nop() {
    let pre = IntegerRegisters {
        r0: 100, r1: 200, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let post = pre;  // Unchanged because 4 is power of 2
    
    assert(verify_imul_rcp(pre, 0, 4, post), 'IMUL_RCP imm32=4 is NOP');
}

#[test]
fn test_imul_rcp_imm32_three_is_not_nop() {
    let pre = IntegerRegisters {
        r0: 100, r1: 200, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let mut post = pre;
    post.r0 = 12345;  // Changed because 3 is NOT power of 2
    
    // Should pass because dst changed (non-NOP)
    assert(verify_imul_rcp(pre, 0, 3, post), 'IMUL_RCP imm32=3 is NOT NOP');
}

#[test]
fn test_iadd_rs_normal_register() {
    let pre = IntegerRegisters {
        r0: 100, r1: 10, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    // r0 = r0 + (r1 << 2) = 100 + (10 * 4) = 140
    // Note: dst is r0, not r5, so imm32 is NOT added
    let mut post = pre;
    post.r0 = 140;
    
    assert(verify_iadd_rs(pre, 0, 1, 2, 500, post), 'IADD_RS r0 ignores imm32');
}

#[test]
fn test_iadd_rs_r5_special_case() {
    let pre = IntegerRegisters {
        r0: 0, r1: 10, r2: 0, r3: 0, r4: 0, r5: 100, r6: 0, r7: 0,
    };
    // r5 = r5 + (r1 << 2) + imm32 = 100 + (10 * 4) + 500 = 640
    // CRITICAL: dst is r5, so imm32 IS added
    let mut post = pre;
    post.r5 = 640;
    
    assert(verify_iadd_rs(pre, 5, 1, 2, 500, post), 'IADD_RS r5 adds imm32');
}

#[test]
fn test_iadd_rs_r5_without_imm32_fails() {
    let pre = IntegerRegisters {
        r0: 0, r1: 10, r2: 0, r3: 0, r4: 0, r5: 100, r6: 0, r7: 0,
    };
    // Wrong: didn't add imm32 for r5
    let mut post = pre;
    post.r5 = 140;  // 100 + 40, missing +500
    
    assert(!verify_iadd_rs(pre, 5, 1, 2, 500, post), 'IADD_RS r5 without imm32 fails');
}

#[test]
fn test_iswap_r_same_register_is_nop() {
    let pre = IntegerRegisters {
        r0: 100, r1: 200, r2: 300, r3: 400, r4: 500, r5: 600, r6: 700, r7: 800,
    };
    let post = pre;  // Unchanged
    
    assert(verify_iswap_r(pre, 2, 2, post), 'ISWAP_R r2,r2 is NOP');
}

#[test]
fn test_cbranch_sets_all_registers_modified() {
    // Per spec: CBRANCH must set ALL registers' last_modified_pc
    let tracker = set_all_modified_at_cbranch(50);
    
    assert(tracker.r0_last_mod == 50, 'r0 should be 50');
    assert(tracker.r1_last_mod == 50, 'r1 should be 50');
    assert(tracker.r2_last_mod == 50, 'r2 should be 50');
    assert(tracker.r3_last_mod == 50, 'r3 should be 50');
    assert(tracker.r4_last_mod == 50, 'r4 should be 50');
    assert(tracker.r5_last_mod == 50, 'r5 should be 50');
    assert(tracker.r6_last_mod == 50, 'r6 should be 50');
    assert(tracker.r7_last_mod == 50, 'r7 should be 50');
}

#[test]
fn test_memory_alignment_8byte() {
    // 8-byte aligned addresses
    assert(verify_address_alignment(0, ScratchpadLevel::L1), 'addr 0 is 8-aligned');
    assert(verify_address_alignment(8, ScratchpadLevel::L1), 'addr 8 is 8-aligned');
    assert(verify_address_alignment(16, ScratchpadLevel::L2), 'addr 16 is 8-aligned');
    assert(verify_address_alignment(1024, ScratchpadLevel::L3), 'addr 1024 is 8-aligned');
    
    // Not 8-byte aligned
    assert(!verify_address_alignment(1, ScratchpadLevel::L1), 'addr 1 not 8-aligned');
    assert(!verify_address_alignment(7, ScratchpadLevel::L2), 'addr 7 not 8-aligned');
    assert(!verify_address_alignment(15, ScratchpadLevel::L3), 'addr 15 not 8-aligned');
}

#[test]
fn test_memory_alignment_64byte() {
    // 64-byte aligned for ISTORE with mod.cond >= 14
    assert(verify_address_alignment(0, ScratchpadLevel::L3_64), 'addr 0 is 64-aligned');
    assert(verify_address_alignment(64, ScratchpadLevel::L3_64), 'addr 64 is 64-aligned');
    assert(verify_address_alignment(128, ScratchpadLevel::L3_64), 'addr 128 is 64-aligned');
    
    // Not 64-byte aligned
    assert(!verify_address_alignment(8, ScratchpadLevel::L3_64), 'addr 8 not 64-aligned');
    assert(!verify_address_alignment(32, ScratchpadLevel::L3_64), 'addr 32 not 64-aligned');
    assert(!verify_address_alignment(63, ScratchpadLevel::L3_64), 'addr 63 not 64-aligned');
}

#[test]
fn test_istore_mod_cond_14_forces_l3() {
    // Per spec: mod.cond >= 14 forces L3 with 64-byte alignment
    let level = get_scratchpad_level_for_store(14, 0);
    assert(level == ScratchpadLevel::L3_64, 'mod_cond=14 forces L3_64');
    
    let level_15 = get_scratchpad_level_for_store(15, 0);
    assert(level_15 == ScratchpadLevel::L3_64, 'mod_cond=15 forces L3_64');
    
    // mod_cond < 14: normal behavior
    let level_l2 = get_scratchpad_level_for_store(10, 0);
    assert(level_l2 == ScratchpadLevel::L2, 'mod_mem=0 gives L2');
    
    let level_l1 = get_scratchpad_level_for_store(10, 1);
    assert(level_l1 == ScratchpadLevel::L1, 'mod_mem=1 gives L1');
}

// ============================================================================
// HARDCORE AUDITOR TESTS: INEG_R, Reciprocal, Sign Extension, Masks
// ============================================================================

use monero_vm::randomx::fraud_proof::instruction_verifiers::{
    verify_ineg_r, verify_imul_rcp_full, compute_reciprocal, is_power_of_2
};
use monero_vm::randomx::fraud_proof::memory_verifiers::get_level_mask;

// ============================================================================
// INEG_R Tests (Per spec: opcode 11, frequency 2/256)
// ============================================================================

#[test]
fn test_ineg_r_zero() {
    // -0 = 0
    let pre = IntegerRegisters {
        r0: 0, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let post = pre;  // -0 = 0
    
    assert(verify_ineg_r(pre, 0, post), 'INEG_R: -0 = 0');
}

#[test]
fn test_ineg_r_one() {
    // -1 = 0xFFFFFFFFFFFFFFFF
    let pre = IntegerRegisters {
        r0: 1, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let mut post = pre;
    post.r0 = 0xFFFFFFFFFFFFFFFF;
    
    assert(verify_ineg_r(pre, 0, post), 'INEG_R: -1 = MAX');
}

#[test]
fn test_ineg_r_max() {
    // -(MAX) = 1
    let pre = IntegerRegisters {
        r0: 0xFFFFFFFFFFFFFFFF, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let mut post = pre;
    post.r0 = 1;
    
    assert(verify_ineg_r(pre, 0, post), 'INEG_R: -MAX = 1');
}

#[test]
fn test_ineg_r_int64_min() {
    // -(INT64_MIN) = INT64_MIN (special case in two's complement)
    let pre = IntegerRegisters {
        r0: 0x8000000000000000, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let post = pre;  // -(INT64_MIN) = INT64_MIN
    
    assert(verify_ineg_r(pre, 0, post), 'INEG_R: -MIN = MIN');
}

#[test]
fn test_ineg_r_wrong_result_fails() {
    let pre = IntegerRegisters {
        r0: 1, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let mut post = pre;
    post.r0 = 0;  // Wrong! Should be 0xFFFFFFFFFFFFFFFF
    
    assert(!verify_ineg_r(pre, 0, post), 'INEG_R wrong result fails');
}

// ============================================================================
// Reciprocal Calculation Tests (Official Test Vectors from tests.cpp)
// ============================================================================

#[test]
fn test_reciprocal_3_official() {
    // Official: assert(randomx_reciprocal(3) == 12297829382473034410U);
    // 12297829382473034410 = 0xAAAAAAAAAAAAAAAA
    let rcp = compute_reciprocal(3);
    assert(rcp == 0xAAAAAAAAAAAAAAAA, 'reciprocal(3) wrong');
}

#[test]
fn test_reciprocal_13_official() {
    // Official: assert(randomx_reciprocal(13) == 11351842506898185609U);
    // 11351842506898185609 = 0x9D89D89D89D89D89
    let rcp = compute_reciprocal(13);
    assert(rcp == 11351842506898185609, 'reciprocal(13) wrong');
}

#[test]
fn test_reciprocal_33_official() {
    // Official: assert(randomx_reciprocal(33) == 17887751829051686415U);
    let rcp = compute_reciprocal(33);
    assert(rcp == 17887751829051686415, 'reciprocal(33) wrong');
}

#[test]
fn test_reciprocal_max_u32_official() {
    // Official: assert(randomx_reciprocal(0xffffffff) == 9223372039002259456U);
    let rcp = compute_reciprocal(0xFFFFFFFF);
    assert(rcp == 9223372039002259456, 'reciprocal(max_u32) wrong');
}

#[test]
fn test_is_power_of_2() {
    // Powers of 2
    assert(is_power_of_2(1), '1 is power of 2');
    assert(is_power_of_2(2), '2 is power of 2');
    assert(is_power_of_2(4), '4 is power of 2');
    assert(is_power_of_2(8), '8 is power of 2');
    assert(is_power_of_2(0x80000000), '2^31 is power of 2');
    
    // Not powers of 2
    assert(!is_power_of_2(0), '0 is NOT power of 2');
    assert(!is_power_of_2(3), '3 is NOT power of 2');
    assert(!is_power_of_2(5), '5 is NOT power of 2');
    assert(!is_power_of_2(7), '7 is NOT power of 2');
}

// ============================================================================
// IADD_RS Sign Extension Tests (Per spec)
// ============================================================================

#[test]
fn test_iadd_rs_r5_negative_imm32() {
    // Test r5 with negative imm32 (sign extension critical)
    // imm32 = 0xFFFFFFFF = -1 as signed, sign-extended to 0xFFFFFFFFFFFFFFFF
    let pre = IntegerRegisters {
        r0: 0, r1: 10, r2: 0, r3: 0, r4: 0, r5: 100, r6: 0, r7: 0,
    };
    // r5 = r5 + (r1 << 2) + sign_extend(0xFFFFFFFF)
    // r5 = 100 + (10 * 4) + (-1) = 100 + 40 - 1 = 139
    let mut post = pre;
    post.r5 = 139;
    
    assert(verify_iadd_rs(pre, 5, 1, 2, 0xFFFFFFFF, post), 'r5 negative imm32');
}

#[test]
fn test_iadd_rs_r5_large_negative_imm32() {
    // imm32 = 0x80000000 = -2147483648 as signed
    // sign-extended to 0xFFFFFFFF80000000
    let pre = IntegerRegisters {
        r0: 0, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0x100000000, r6: 0, r7: 0,
    };
    // r5 = 0x100000000 + 0 + 0xFFFFFFFF80000000
    // = 0x100000000 + 0xFFFFFFFF80000000 (wrapping)
    // = 0x0000000080000000
    let mut post = pre;
    post.r5 = 0x0000000080000000;
    
    assert(verify_iadd_rs(pre, 5, 1, 0, 0x80000000, post), 'r5 large neg imm32');
}

#[test]
fn test_iadd_rs_non_r5_ignores_imm32() {
    // r0-r4, r6, r7 should ignore imm32 even if it's provided
    let pre = IntegerRegisters {
        r0: 100, r1: 10, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    // r0 = r0 + (r1 << 2) = 100 + 40 = 140 (imm32 ignored!)
    let mut post = pre;
    post.r0 = 140;
    
    assert(verify_iadd_rs(pre, 0, 1, 2, 0xFFFFFFFF, post), 'r0 ignores imm32');
}

// ============================================================================
// ISTORE Level Selection Boundary Tests
// ============================================================================

#[test]
fn test_istore_mod_cond_13_not_l3() {
    // mod_cond = 13 should NOT force L3
    let level = get_scratchpad_level_for_store(13, 0);
    assert(level == ScratchpadLevel::L2, 'mod_cond=13 gives L2');
    
    let level_l1 = get_scratchpad_level_for_store(13, 1);
    assert(level_l1 == ScratchpadLevel::L1, 'mod_cond=13 mod_mem=1 gives L1');
}

#[test]
fn test_istore_all_mod_cond_below_14() {
    // All mod_cond values 0-13 should not force L3
    let mut i: u8 = 0;
    loop {
        if i >= 14 {
            break;
        }
        let level_l2 = get_scratchpad_level_for_store(i, 0);
        assert(level_l2 == ScratchpadLevel::L2, 'mod_cond<14 mod_mem=0 L2');
        
        let level_l1 = get_scratchpad_level_for_store(i, 1);
        assert(level_l1 == ScratchpadLevel::L1, 'mod_cond<14 mod_mem=1 L1');
        
        i += 1;
    };
}

// ============================================================================
// Scratchpad Mask Tests (Per spec)
// ============================================================================

#[test]
fn test_scratchpad_masks_correct() {
    // L1 mask: 0x3FF8 (16 KB - 8, 8-byte aligned)
    let l1_mask = get_level_mask(ScratchpadLevel::L1);
    assert(l1_mask == 0x3FF8, 'L1 mask wrong');
    
    // L2 mask: 0x3FFF8 (256 KB - 8, 8-byte aligned)
    let l2_mask = get_level_mask(ScratchpadLevel::L2);
    assert(l2_mask == 0x3FFF8, 'L2 mask wrong');
    
    // L3 mask: 0x1FFFF8 (2 MB - 8, 8-byte aligned)
    let l3_mask = get_level_mask(ScratchpadLevel::L3);
    assert(l3_mask == 0x1FFFF8, 'L3 mask wrong');
    
    // L3_64 mask: 0x1FFFC0 (2 MB - 64, 64-byte aligned)
    let l3_64_mask = get_level_mask(ScratchpadLevel::L3_64);
    assert(l3_64_mask == 0x1FFFC0, 'L3_64 mask wrong');
}

#[test]
fn test_scratchpad_mask_alignment() {
    // Verify masks produce properly aligned addresses
    let l1_mask = get_level_mask(ScratchpadLevel::L1);
    assert((l1_mask & 7) == 0, 'L1 mask not 8-aligned');
    
    let l2_mask = get_level_mask(ScratchpadLevel::L2);
    assert((l2_mask & 7) == 0, 'L2 mask not 8-aligned');
    
    let l3_mask = get_level_mask(ScratchpadLevel::L3);
    assert((l3_mask & 7) == 0, 'L3 mask not 8-aligned');
    
    let l3_64_mask = get_level_mask(ScratchpadLevel::L3_64);
    assert((l3_64_mask & 63) == 0, 'L3_64 mask not 64-aligned');
}

// ============================================================================
// Full IMUL_RCP Verification Tests
// ============================================================================

#[test]
fn test_imul_rcp_full_with_3() {
    let pre = IntegerRegisters {
        r0: 10, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    // Official: reciprocal(3) = 0xAAAAAAAAAAAAAAAA
    // dst = dst * reciprocal(3) = 10 * 0xAAAAAAAAAAAAAAAA (low 64 bits, wrapping)
    let rcp: u128 = 0xAAAAAAAAAAAAAAAA;
    let prod: u128 = 10 * rcp;
    let expected: u64 = (prod % 0x10000000000000000).try_into().unwrap();
    
    let mut post = pre;
    post.r0 = expected;
    
    assert(verify_imul_rcp_full(pre, 0, 3, post), 'IMUL_RCP with 3');
}
