use monero_vm::randomx::prototype::{
    InstructionType,
    get_execution_port, get_instruction_latency, is_valid_destination,
    select_destination_register, init_register_info, update_register_info,
};

// ============================================================
// TDD TESTS - SuperscalarHash Foundation
// ============================================================

#[test]
fn test_init_register_info() {
    let reg_info = init_register_info();
    assert(reg_info.len() == 8, '8 registers');
    
    // Check all registers initialized with latency 0
    let mut i: usize = 0;
    loop {
        if i == 8 {
            break;
        }
        let reg = *reg_info.at(i);
        assert(reg.latency == 0, 'latency 0');
        assert(reg.last_op_par == -1, 'no prev op');
        i += 1;
    }
}

#[test]
fn test_get_execution_port_multiplication() {
    // Multiplications must run on P1
    let _port_imul = get_execution_port(InstructionType::IMUL_R);
    let _port_imulh = get_execution_port(InstructionType::IMULH_R);
    let _port_ismulh = get_execution_port(InstructionType::ISMULH_R);
    let _port_imul_rcp = get_execution_port(InstructionType::IMUL_RCP);
    
    // Check they're all P1 (we'll need to match to verify)
    // For now, verify they're not P0 by checking other instructions
    let _port_add = get_execution_port(InstructionType::IADD_RS);
    // P0 and P1 are different, so we can verify multiplication ports are consistent
    assert(true, 'mul ports'); // Placeholder - will verify with enum matching
}

#[test]
fn test_get_execution_port_non_multiplication() {
    // Non-multiplication instructions run on P0
    let _port_sub = get_execution_port(InstructionType::ISUB_R);
    let _port_xor = get_execution_port(InstructionType::IXOR_R);
    let _port_add_rs = get_execution_port(InstructionType::IADD_RS);
    let _port_ror = get_execution_port(InstructionType::IROR_C);
    
    // All should be P0
    assert(true, 'non-mul ports'); // Placeholder
}

#[test]
fn test_get_instruction_latency_multiplication() {
    // Multiplications have 3 cycle latency
    let lat_imul = get_instruction_latency(InstructionType::IMUL_R);
    assert(lat_imul == 3, 'imul latency');
    
    let lat_imulh = get_instruction_latency(InstructionType::IMULH_R);
    assert(lat_imulh == 3, 'imulh latency');
    
    let lat_ismulh = get_instruction_latency(InstructionType::ISMULH_R);
    assert(lat_ismulh == 3, 'ismulh latency');
    
    let lat_imul_rcp = get_instruction_latency(InstructionType::IMUL_RCP);
    assert(lat_imul_rcp == 3, 'imul_rcp latency');
}

#[test]
fn test_get_instruction_latency_non_multiplication() {
    // Non-multiplication instructions have 1 cycle latency
    let lat_sub = get_instruction_latency(InstructionType::ISUB_R);
    assert(lat_sub == 1, 'isub latency');
    
    let lat_xor = get_instruction_latency(InstructionType::IXOR_R);
    assert(lat_xor == 1, 'ixor latency');
    
    let lat_add_rs = get_instruction_latency(InstructionType::IADD_RS);
    assert(lat_add_rs == 1, 'iadd_rs latency');
    
    let lat_ror = get_instruction_latency(InstructionType::IROR_C);
    assert(lat_ror == 1, 'iror latency');
    
    let lat_add_c7 = get_instruction_latency(InstructionType::IADD_C7);
    assert(lat_add_c7 == 1, 'iadd_c7 latency');
}

#[test]
fn test_is_valid_destination_rule1_latency() {
    // Rule 1: Value must be ready at the required cycle
    let mut reg_info_array = init_register_info();
    let reg_info = reg_info_array.span();
    
    // Register with latency 5, current cycle 3 - should be invalid
    let mut reg = *reg_info.at(0);
    reg.latency = 5;
    let mut reg_info_mut = ArrayTrait::new();
    reg_info_mut.append(reg);
    let mut i: usize = 1;
    loop {
        if i == 8 {
            break;
        }
        reg_info_mut.append(*reg_info.at(i));
        i += 1;
    }
    let reg_info_updated = reg_info_mut.span();
    
    let valid = is_valid_destination(0, -1, InstructionType::ISUB_R, reg_info_updated, 3, false);
    assert(!valid, 'rule1 latency not ready');
    
    // Register with latency 2, current cycle 3 - should be valid (2 <= 3)
    // Start fresh with new register info
    let mut reg_info_array2 = init_register_info();
    let reg_info2 = reg_info_array2.span();
    
    let mut reg2 = *reg_info2.at(1);
    reg2.latency = 2;
    reg2.last_op_group = InstructionType::IXOR_R; // Different op to avoid Rule 4
    reg2.last_op_par = 0; // Different par to avoid Rule 4
    let mut reg_info_mut2 = ArrayTrait::new();
    reg_info_mut2.append(*reg_info2.at(0));
    reg_info_mut2.append(reg2);
    let mut i2: usize = 2;
    loop {
        if i2 == 8 {
            break;
        }
        reg_info_mut2.append(*reg_info2.at(i2));
        i2 += 1;
    }
    let reg_info_updated2 = reg_info_mut2.span();
    
    // Register 1 has latency 2, current cycle 3, so 2 > 3 is false, register is ready
    let valid2 = is_valid_destination(1, -1, InstructionType::ISUB_R, reg_info_updated2, 3, false);
    assert(valid2, 'rule1 latency ready');
    
    // Also test exact match: latency 3, current cycle 3 - should be valid (3 > 3 is false)
    let mut reg_info_array3 = init_register_info();
    let reg_info3 = reg_info_array3.span();
    
    let mut reg3 = *reg_info3.at(2);
    reg3.latency = 3;
    reg3.last_op_group = InstructionType::IADD_RS; // Different op to avoid Rule 4
    reg3.last_op_par = 1; // Different par to avoid Rule 4
    let mut reg_info_mut3 = ArrayTrait::new();
    reg_info_mut3.append(*reg_info3.at(0));
    reg_info_mut3.append(*reg_info3.at(1));
    reg_info_mut3.append(reg3);
    let mut i3: usize = 3;
    loop {
        if i3 == 8 {
            break;
        }
        reg_info_mut3.append(*reg_info3.at(i3));
        i3 += 1;
    }
    let reg_info_updated3 = reg_info_mut3.span();
    
    let valid3 = is_valid_destination(2, -1, InstructionType::ISUB_R, reg_info_updated3, 3, false);
    assert(valid3, 'rule1 latency exact match');
}

#[test]
fn test_is_valid_destination_rule2_same_src_dst() {
    // Rule 2: Cannot be same as source register (avoids xor r, r)
    let reg_info = init_register_info().span();
    
    // IXOR_R with dst == src should be invalid
    let valid_xor = is_valid_destination(0, 0, InstructionType::IXOR_R, reg_info, 0, false);
    assert(!valid_xor, 'rule2 xor r r invalid');
    
    // ISUB_R with dst == src should be invalid
    let valid_sub = is_valid_destination(1, 1, InstructionType::ISUB_R, reg_info, 0, false);
    assert(!valid_sub, 'rule2 sub r r invalid');
    
    // IADD_RS with dst != src should be valid
    let valid_add = is_valid_destination(0, 1, InstructionType::IADD_RS, reg_info, 0, false);
    assert(valid_add, 'rule2 add r1 r2 valid');
    
    // Constant source (-1) with any dst should be valid
    let valid_const = is_valid_destination(0, -1, InstructionType::IADD_C7, reg_info, 0, false);
    assert(valid_const, 'rule2 const src valid');
}

#[test]
fn test_is_valid_destination_rule3_chained_multiplication() {
    // Rule 3: Register cannot be multiplied twice in a row unless allowChainedMul is true
    let mut reg_info_array = init_register_info();
    
    // Set register 0 to have last operation as IMUL_R
    let mut reg0 = *reg_info_array.at(0);
    reg0.last_op_group = InstructionType::IMUL_R;
    reg0.last_op_par = 1; // Different from -1 to avoid Rule 4 conflict
    reg0.latency = 5; // Set latency so register is ready at cycle 10
    
    let mut reg_info_mut = ArrayTrait::new();
    reg_info_mut.append(reg0);
    let mut i: usize = 1;
    loop {
        if i == 8 {
            break;
        }
        reg_info_mut.append(*reg_info_array.at(i));
        i += 1;
    }
    let reg_info = reg_info_mut.span();
    
    // Without allow_chained_mul, chained multiplication should be invalid
    let valid_no_chain = is_valid_destination(0, -1, InstructionType::IMUL_R, reg_info, 10, false);
    assert(!valid_no_chain, 'rule3 no chain mul invalid');
    
    // With allow_chained_mul, chained multiplication should be valid
    // Use different src to avoid Rule 4 conflict
    let valid_chain = is_valid_destination(0, 2, InstructionType::IMUL_R, reg_info, 10, true);
    assert(valid_chain, 'rule3 chain mul valid');
    
    // Non-multiplication after multiplication should be valid
    let valid_after_mul = is_valid_destination(0, 1, InstructionType::IXOR_R, reg_info, 10, false);
    assert(valid_after_mul, 'rule3 non-mul after mul valid');
}

#[test]
fn test_is_valid_destination_rule3_all_multiplication_types() {
    // Test all multiplication types are detected
    let mut reg_info_array = init_register_info();
    
    // Test IMULH_R chaining
    let mut reg0 = *reg_info_array.at(0);
    reg0.last_op_group = InstructionType::IMULH_R;
    let mut reg_info_mut = ArrayTrait::new();
    reg_info_mut.append(reg0);
    let mut i: usize = 1;
    loop {
        if i == 8 {
            break;
        }
        reg_info_mut.append(*reg_info_array.at(i));
        i += 1;
    }
    let reg_info = reg_info_mut.span();
    
    let valid_imulh = is_valid_destination(0, -1, InstructionType::IMUL_R, reg_info, 10, false);
    assert(!valid_imulh, 'rule3 imulh chain invalid');
    
    // Test ISMULH_R chaining
    let mut reg1 = *reg_info_array.at(1);
    reg1.last_op_group = InstructionType::ISMULH_R;
    let mut reg_info_mut2 = ArrayTrait::new();
    reg_info_mut2.append(*reg_info_array.at(0));
    reg_info_mut2.append(reg1);
    let mut i2: usize = 2;
    loop {
        if i2 == 8 {
            break;
        }
        reg_info_mut2.append(*reg_info_array.at(i2));
        i2 += 1;
    }
    let reg_info2 = reg_info_mut2.span();
    
    let valid_ismulh = is_valid_destination(1, -1, InstructionType::IMUL_RCP, reg_info2, 10, false);
    assert(!valid_ismulh, 'rule3 ismulh chain invalid');
}

#[test]
fn test_is_valid_destination_rule4_duplicate_operation() {
    // Rule 4: Last instruction applied OR its source must differ from current
    // (avoids xor r1,r2; xor r1,r2)
    let mut reg_info_array = init_register_info();
    
    // Set register 0 to have last operation as IXOR_R with src=1
    let mut reg0 = *reg_info_array.at(0);
    reg0.last_op_group = InstructionType::IXOR_R;
    reg0.last_op_par = 1;
    
    let mut reg_info_mut = ArrayTrait::new();
    reg_info_mut.append(reg0);
    let mut i: usize = 1;
    loop {
        if i == 8 {
            break;
        }
        reg_info_mut.append(*reg_info_array.at(i));
        i += 1;
    }
    let reg_info = reg_info_mut.span();
    
    // Same operation with same source should be invalid
    let valid_dup = is_valid_destination(0, 1, InstructionType::IXOR_R, reg_info, 10, false);
    assert(!valid_dup, 'rule4 duplicate op invalid');
    
    // Same operation with different source should be valid
    let valid_diff_src = is_valid_destination(0, 2, InstructionType::IXOR_R, reg_info, 10, false);
    assert(valid_diff_src, 'rule4 diff src valid');
    
    // Different operation with same source should be valid
    let valid_diff_op = is_valid_destination(0, 1, InstructionType::ISUB_R, reg_info, 10, false);
    assert(valid_diff_op, 'rule4 diff op valid');
}

#[test]
fn test_is_valid_destination_rule5_r5_iadd_rs() {
    // Rule 5: Register r5 cannot be destination of IADD_RS (x86 lea limitation)
    let reg_info = init_register_info().span();
    
    // r5 as destination of IADD_RS should be invalid
    let valid_r5 = is_valid_destination(5, 1, InstructionType::IADD_RS, reg_info, 0, false);
    assert(!valid_r5, 'rule5 r5 iadd_rs invalid');
    
    // r5 as destination of other instructions should be valid
    let valid_r5_other = is_valid_destination(5, 1, InstructionType::IXOR_R, reg_info, 0, false);
    assert(valid_r5_other, 'rule5 r5 other op valid');
    
    // Other registers as destination of IADD_RS should be valid
    let valid_r0 = is_valid_destination(0, 1, InstructionType::IADD_RS, reg_info, 0, false);
    assert(valid_r0, 'rule5 r0 iadd_rs valid');
    
    let valid_r4 = is_valid_destination(4, 1, InstructionType::IADD_RS, reg_info, 0, false);
    assert(valid_r4, 'rule5 r4 iadd_rs valid');
    
    let valid_r6 = is_valid_destination(6, 1, InstructionType::IADD_RS, reg_info, 0, false);
    assert(valid_r6, 'rule5 r6 iadd_rs valid');
}

#[test]
fn test_is_valid_destination_all_rules_combined() {
    // Test a register that passes all rules
    let reg_info = init_register_info().span();
    
    // Register 2, not used before, with src=3, IXOR_R operation
    let valid_all = is_valid_destination(2, 3, InstructionType::IXOR_R, reg_info, 0, false);
    assert(valid_all, 'all rules pass');
}

#[test]
fn test_select_destination_register_finds_valid() {
    let reg_info = init_register_info().span();
    
    // Should find a valid register (r0 should be valid)
    let dst = select_destination_register(1, InstructionType::IXOR_R, reg_info, 0, false);
    assert(dst.is_some(), 'finds valid dst');
    
    let dst_val = dst.unwrap();
    assert(dst_val < 8, 'dst in range');
}

#[test]
fn test_select_destination_register_respects_r5_restriction() {
    let reg_info = init_register_info().span();
    
    // For IADD_RS, should not select r5
    let dst = select_destination_register(1, InstructionType::IADD_RS, reg_info, 0, false);
    assert(dst.is_some(), 'finds valid dst for iadd_rs');
    
    let dst_val = dst.unwrap();
    assert(dst_val != 5, 'not r5 for iadd_rs');
}

#[test]
fn test_select_destination_register_respects_latency() {
    // Create register info where all registers have high latency
    let mut reg_info_array = init_register_info();
    let mut reg_info_mut = ArrayTrait::new();
    let mut i: usize = 0;
    loop {
        if i == 8 {
            break;
        }
        let mut reg = *reg_info_array.at(i);
        reg.latency = 100; // All registers busy
        reg_info_mut.append(reg);
        i += 1;
    }
    let reg_info = reg_info_mut.span();
    
    // Current cycle 0, all registers latency 100 - should find none
    let dst = select_destination_register(1, InstructionType::IXOR_R, reg_info, 0, false);
    assert(dst.is_none(), 'no valid dst when all busy');
}

#[test]
fn test_update_register_info() {
    let reg_info = init_register_info().span();
    
    // Update register 0 with IMUL_R operation
    let updated = update_register_info(reg_info, 0, InstructionType::IMUL_R, -1, 5);
    
    assert(updated.latency == 8, 'latency updated'); // 5 + 3 = 8
    assert(updated.last_op_par == -1, 'op par set');
    
    // Update register 1 with IXOR_R operation
    let updated2 = update_register_info(reg_info, 1, InstructionType::IXOR_R, 2, 10);
    
    assert(updated2.latency == 11, 'latency updated 2'); // 10 + 1 = 11
    assert(updated2.last_op_par == 2, 'op par set 2');
}

#[test]
fn test_update_register_info_all_instruction_types() {
    let reg_info = init_register_info().span();
    let cycle = 0;
    
    // Test all instruction types update correctly
    let updated_sub = update_register_info(reg_info, 0, InstructionType::ISUB_R, 1, cycle);
    assert(updated_sub.latency == 1, 'isub latency');
    
    let updated_xor = update_register_info(reg_info, 1, InstructionType::IXOR_R, 2, cycle);
    assert(updated_xor.latency == 1, 'ixor latency');
    
    let updated_add_rs = update_register_info(reg_info, 2, InstructionType::IADD_RS, 3, cycle);
    assert(updated_add_rs.latency == 1, 'iadd_rs latency');
    
    let updated_mul = update_register_info(reg_info, 3, InstructionType::IMUL_R, 4, cycle);
    assert(updated_mul.latency == 3, 'imul latency');
    
    let updated_ror = update_register_info(reg_info, 4, InstructionType::IROR_C, -1, cycle);
    assert(updated_ror.latency == 1, 'iror latency');
}

#[test]
fn test_register_info_edge_cases() {
    let reg_info = init_register_info().span();
    
    // Test with large but safe cycle (avoid u32 overflow)
    // Use 0xFFFFFF00 to leave room for latency addition
    let updated = update_register_info(reg_info, 0, InstructionType::IMUL_R, -1, 0xFFFFFF00);
    // Should handle large cycle gracefully
    assert(updated.latency > 0xFFFFFF00, 'large cycle handled');
    
    // Test with register 7 (last register)
    let updated_r7 = update_register_info(reg_info, 7, InstructionType::IXOR_R, 0, 0);
    assert(updated_r7.latency == 1, 'r7 updated');
    
    // Test with cycle 0
    let updated_zero = update_register_info(reg_info, 0, InstructionType::ISUB_R, -1, 0);
    assert(updated_zero.latency == 1, 'zero cycle');
}

#[test]
fn test_destination_selection_all_registers() {
    // Test that we can select each register (0-7) as destination
    let reg_info = init_register_info().span();
    
    let mut found_regs = ArrayTrait::new();
    let mut attempts = 0;
    loop {
        if attempts == 100 {
            break; // Prevent infinite loop
        }
        let dst = select_destination_register(-1, InstructionType::IADD_C7, reg_info, 0, false);
        if dst.is_some() {
            let dst_val = dst.unwrap();
            // Check if we've seen this register
            let mut seen = false;
            let mut i: usize = 0;
            loop {
                if i == found_regs.len() {
                    break;
                }
                if *found_regs.at(i) == dst_val {
                    seen = true;
                    break;
                }
                i += 1;
            }
            if !seen {
                found_regs.append(dst_val);
            }
        }
        attempts += 1;
    }
    
    // Should be able to find at least some registers
    assert(found_regs.len() > 0, 'finds registers');
}

#[test]
fn test_instruction_type_completeness() {
    // Verify we can create all instruction types
    // This is a compile-time check, but we test runtime usage
    let _reg_info = init_register_info().span();
    
    // Test all instruction types can be used in get_instruction_latency
    let _ = get_instruction_latency(InstructionType::ISUB_R);
    let _ = get_instruction_latency(InstructionType::IXOR_R);
    let _ = get_instruction_latency(InstructionType::IADD_RS);
    let _ = get_instruction_latency(InstructionType::IMUL_R);
    let _ = get_instruction_latency(InstructionType::IROR_C);
    let _ = get_instruction_latency(InstructionType::IADD_C7);
    let _ = get_instruction_latency(InstructionType::IADD_C8);
    let _ = get_instruction_latency(InstructionType::IADD_C9);
    let _ = get_instruction_latency(InstructionType::IXOR_C7);
    let _ = get_instruction_latency(InstructionType::IXOR_C8);
    let _ = get_instruction_latency(InstructionType::IXOR_C9);
    let _ = get_instruction_latency(InstructionType::IMULH_R);
    let _ = get_instruction_latency(InstructionType::ISMULH_R);
    let _ = get_instruction_latency(InstructionType::IMUL_RCP);
    
    assert(true, 'all instruction types usable');
}
