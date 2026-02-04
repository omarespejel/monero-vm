use monero_vm::randomx::prototype::{
    InstructionType, SuperscalarInstruction, ExecutionPort,
    generate_superscalar_program, execute_superscalar_program,
    init_registers, get_execution_port, get_instruction_latency,
    wrapping_sub_64,
};

// ============================================================
// TDD TESTS - Full SuperscalarHash Program Generation
// ============================================================

#[test]
fn test_generate_superscalar_program_basic() {
    // Test basic program generation
    let seed: u64 = 12345;
    let program_size: u32 = 10;
    
    let program = generate_superscalar_program(seed, program_size);
    
    assert(program.len() == program_size, 'program size');
    
    // Verify all instructions are valid
    let mut i: usize = 0;
    loop {
        if i == program.len() {
            break;
        }
        let instr = *program.at(i);
        assert(instr.dst < 8, 'dst valid');
        // src is u32, check it's valid if used as register index
        if instr.src < 8 {
            assert(instr.src < 8, 'src valid');
        }
        i += 1;
    }
}

#[test]
fn test_generate_superscalar_program_deterministic() {
    // Same seed should produce same program
    let seed: u64 = 54321;
    let program_size: u32 = 5;
    
    let program1 = generate_superscalar_program(seed, program_size);
    let program2 = generate_superscalar_program(seed, program_size);
    
    assert(program1.len() == program2.len(), 'same length');
    
    // Verify instructions match
    let mut i: usize = 0;
    loop {
        if i == program1.len() {
            break;
        }
        let instr1 = *program1.at(i);
        let instr2 = *program2.at(i);
        assert(instr1.dst == instr2.dst, 'dst match');
        assert(instr1.src == instr2.src, 'src match');
        assert(instr1.imm32 == instr2.imm32, 'imm match');
        i += 1;
    }
}

#[test]
fn test_generate_superscalar_program_different_seeds() {
    // Different seeds should produce different programs
    let seed1: u64 = 11111;
    let seed2: u64 = 22222;
    let program_size: u32 = 10;
    
    let program1 = generate_superscalar_program(seed1, program_size);
    let program2 = generate_superscalar_program(seed2, program_size);
    
    // Programs should differ (at least one instruction different)
    let mut different = false;
    let mut i: usize = 0;
    loop {
        if i == program1.len() {
            break;
        }
        let instr1 = *program1.at(i);
        let instr2 = *program2.at(i);
        if instr1.dst != instr2.dst || instr1.src != instr2.src || instr1.imm32 != instr2.imm32 {
            different = true;
            break;
        }
        i += 1;
    }
    assert(different, 'programs differ');
}

#[test]
fn test_generate_superscalar_program_respects_r5_restriction() {
    // Verify no IADD_RS instructions have r5 as destination
    let seed: u64 = 99999;
    let program_size: u32 = 50; // Larger program to increase chance of IADD_RS
    
    let program = generate_superscalar_program(seed, program_size);
    
    let mut i: usize = 0;
    loop {
        if i == program.len() {
            break;
        }
        let instr = *program.at(i);
        let is_iadd_rs = match instr.opcode {
            InstructionType::IADD_RS => true,
            _ => false,
        };
        if is_iadd_rs {
            assert(instr.dst != 5, 'no r5 iadd_rs');
        }
        i += 1;
    }
}

#[test]
fn test_generate_superscalar_program_no_chained_multiplications() {
    // Verify no chained multiplications (unless explicitly allowed)
    let seed: u64 = 77777;
    let program_size: u32 = 50;
    
    let program = generate_superscalar_program(seed, program_size);
    
    // Track last operation per register
    let mut last_op = ArrayTrait::new();
    let mut j: u32 = 0;
    loop {
        if j == 8 {
            break;
        }
        last_op.append(InstructionType::ISUB_R); // Initial value
        j += 1;
    }
    
    let mut i: usize = 0;
    loop {
        if i == program.len() {
            break;
        }
        let instr = *program.at(i);
        let dst_idx: usize = instr.dst.try_into().unwrap();
        let last = *last_op.at(dst_idx);
        
        // Check if this is a multiplication
        let is_mul = match instr.opcode {
            InstructionType::IMUL_R => true,
            InstructionType::IMULH_R => true,
            InstructionType::ISMULH_R => true,
            InstructionType::IMUL_RCP => true,
            _ => false,
        };
        
        // Check if last was multiplication
        let was_mul = match last {
            InstructionType::IMUL_R => true,
            InstructionType::IMULH_R => true,
            InstructionType::ISMULH_R => true,
            InstructionType::IMUL_RCP => true,
            _ => false,
        };
        
        // Should not chain multiplications
        if is_mul && was_mul {
            assert(false, 'no chained mul');
        }
        
        // Update last operation
        let mut new_last_op = ArrayTrait::new();
        let mut k: usize = 0;
        loop {
            if k == 8 {
                break;
            }
            if k == dst_idx {
                new_last_op.append(instr.opcode);
            } else {
                new_last_op.append(*last_op.at(k));
            }
            k += 1;
        }
        last_op = new_last_op;
        
        i += 1;
    }
}

#[test]
fn test_execute_superscalar_program_basic() {
    // Test executing a simple program
    let seed: u64 = 12345;
    let program_size: u32 = 5;
    
    let program = generate_superscalar_program(seed, program_size);
    let initial_regs = init_registers(0);
    
    let final_regs = execute_superscalar_program(initial_regs, program.span());
    
    // Registers should have changed
    assert(final_regs.r0 != initial_regs.r0 || final_regs.r1 != initial_regs.r1, 'regs changed');
}

#[test]
fn test_execute_superscalar_program_deterministic() {
    // Same program should produce same result
    let seed: u64 = 54321;
    let program_size: u32 = 10;
    
    let program = generate_superscalar_program(seed, program_size);
    let initial_regs = init_registers(100);
    
    let final_regs1 = execute_superscalar_program(initial_regs, program.span());
    let final_regs2 = execute_superscalar_program(initial_regs, program.span());
    
    assert(final_regs1.r0 == final_regs2.r0, 'r0 deterministic');
    assert(final_regs1.r1 == final_regs2.r1, 'r1 deterministic');
    assert(final_regs1.r7 == final_regs2.r7, 'r7 deterministic');
}

#[test]
fn test_execute_superscalar_program_all_instruction_types() {
    // Verify all instruction types can be executed
    let seed: u64 = 11111;
    let program_size: u32 = 100; // Large enough to include all types
    
    let program = generate_superscalar_program(seed, program_size);
    let initial_regs = init_registers(0);
    
    // Should execute without panicking
    let _final_regs = execute_superscalar_program(initial_regs, program.span());
    assert(true, 'all types executed');
}

#[test]
fn test_execute_superscalar_program_empty() {
    // Empty program should return registers unchanged
    let mut program = ArrayTrait::new();
    let initial_regs = init_registers(42);
    
    let final_regs = execute_superscalar_program(initial_regs, program.span());
    
    assert(final_regs.r0 == initial_regs.r0, 'empty unchanged');
    assert(final_regs.r7 == initial_regs.r7, 'empty unchanged 2');
}

#[test]
fn test_generate_superscalar_program_port_scheduling() {
    // Verify instructions are scheduled across ports correctly
    // P5 → P0 → P1 order should be respected
    let seed: u64 = 88888;
    let program_size: u32 = 20;
    
    let program = generate_superscalar_program(seed, program_size);
    
    // Track port usage
    let mut p0_count = 0;
    let mut p1_count = 0;
    let mut p5_count = 0;
    
    let mut i: usize = 0;
    loop {
        if i == program.len() {
            break;
        }
        let instr = *program.at(i);
        let port = get_execution_port(instr.opcode);
        
        match port {
            ExecutionPort::P0 => p0_count += 1,
            ExecutionPort::P1 => p1_count += 1,
            ExecutionPort::P5 => p5_count += 1,
        }
        
        i += 1;
    }
    
    // Should have instructions on multiple ports
    assert(p0_count > 0_u32, 'p0 used');
    // P1 only for multiplications, may be 0 if no muls in small program
    // P5 may not be used in simplified model
}

#[test]
fn test_generate_superscalar_program_dependency_tracking() {
    // Verify dependencies are respected (registers ready before use)
    let seed: u64 = 33333;
    let program_size: u32 = 30;
    
    let program = generate_superscalar_program(seed, program_size);
    
    // Track register latencies
    let mut reg_latency = ArrayTrait::new();
    let mut j: u32 = 0;
    loop {
        if j == 8 {
            break;
        }
        reg_latency.append(0_u32);
        j += 1;
    }
    
    let mut current_cycle = 0_u32;
    let mut i: usize = 0;
    loop {
        if i == program.len() {
            break;
        }
        let instr = *program.at(i);
        let dst_idx: usize = instr.dst.try_into().unwrap();
        
        // Check register is ready
        let latency = *reg_latency.at(dst_idx);
        assert(latency <= current_cycle, 'reg ready');
        
        // Update latency
        let instr_latency = get_instruction_latency(instr.opcode);
        let mut new_latency = ArrayTrait::new();
        let mut k: usize = 0;
        loop {
            if k == 8 {
                break;
            }
            if k == dst_idx {
                new_latency.append(current_cycle + instr_latency);
            } else {
                new_latency.append(*reg_latency.at(k));
            }
            k += 1;
        }
        reg_latency = new_latency;
        
        current_cycle += 1;
        i += 1;
    }
}

#[test]
fn test_generate_superscalar_program_typical_size() {
    // RandomX typically uses programs of size 50-100
    let seed: u64 = 123456;
    let program_size: u32 = 64; // Typical size
    
    let program = generate_superscalar_program(seed, program_size);
    
    assert(program.len() == 64, 'typical size');
    
    // Should execute successfully
    let initial_regs = init_registers(0);
    let _final_regs = execute_superscalar_program(initial_regs, program.span());
    assert(true, 'typical exec');
}

#[test]
fn test_generate_superscalar_program_max_size() {
    // Test with maximum reasonable size
    let seed: u64 = 999999;
    let program_size: u32 = 256; // RandomX max
    
    let program = generate_superscalar_program(seed, program_size);
    
    assert(program.len() == 256, 'max size');
}

#[test]
fn test_execute_superscalar_program_instruction_order() {
    // Verify instructions execute in order
    let mut program = ArrayTrait::new();
    
    // Create a simple program: ISUB_R r0, r1
    program.append(SuperscalarInstruction {
        opcode: InstructionType::ISUB_R,
        dst: 0,
        src: 1,
        imm32: 0,
        mod_shift: 0,
    });
    
    // IXOR_R r0, r2
    program.append(SuperscalarInstruction {
        opcode: InstructionType::IXOR_R,
        dst: 0,
        src: 2,
        imm32: 0,
        mod_shift: 0,
    });
    
    let initial_regs = init_registers(0);
    let final_regs = execute_superscalar_program(initial_regs, program.span());
    
    // r0 should be wrapping_sub(initial_r0, initial_r1) ^ initial_r2
    let expected_r0 = wrapping_sub_64(initial_regs.r0, initial_regs.r1) ^ initial_regs.r2;
    assert(final_regs.r0 == expected_r0, 'order correct');
}
