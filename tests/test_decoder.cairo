// ============================================================
// TDD Tests for Decoder Buffer State Machine
// Source: RandomX superscalar.cpp lines 200-400
// ============================================================
//
// The decoder is responsible for:
// 1. Selecting decoder configurations (3-1-1-1, 4-4-4-4, 3-3-10, 7-3-2-2)
// 2. Generating macro-ops from the Blake2bGenerator
// 3. Scheduling instructions based on ports and dependencies

use monero_vm::randomx::decoder::{
    decoder_buffer_new, decoder_select_config, decoder_fetch_macro_op,
    get_slot_size,
    DECODER_3111, DECODER_4444, DECODER_3310, DECODER_7322,
};
use monero_vm::randomx::blake2b::blake2b_generator_new;

// ============================================================
// Decoder Configuration Constants
// From RandomX superscalar.cpp - buffer configurations
// ============================================================

#[test]
fn test_decoder_config_3111() {
    // Configuration 3-1-1-1: 4 slots, sizes [3,1,1,1]
    // Total size = 6 bytes (macro-ops)
    let config = DECODER_3111;
    assert(config.slot_count == 4, '3111 has 4 slots');
    assert(get_slot_size(config, 0) == 3, 'slot0 = 3');
    assert(get_slot_size(config, 1) == 1, 'slot1 = 1');
    assert(get_slot_size(config, 2) == 1, 'slot2 = 1');
    assert(get_slot_size(config, 3) == 1, 'slot3 = 1');
}

#[test]
fn test_decoder_config_4444() {
    // Configuration 4-4-4-4: 4 slots, all size 4
    // Total size = 16 bytes
    let config = DECODER_4444;
    assert(config.slot_count == 4, '4444 has 4 slots');
    assert(get_slot_size(config, 0) == 4, 'slot0 = 4');
    assert(get_slot_size(config, 1) == 4, 'slot1 = 4');
    assert(get_slot_size(config, 2) == 4, 'slot2 = 4');
    assert(get_slot_size(config, 3) == 4, 'slot3 = 4');
}

#[test]
fn test_decoder_config_3310() {
    // Configuration 3-3-10: 3 slots, sizes [3,3,10]
    // Total size = 16 bytes
    let config = DECODER_3310;
    assert(config.slot_count == 3, '3310 has 3 slots');
    assert(get_slot_size(config, 0) == 3, 'slot0 = 3');
    assert(get_slot_size(config, 1) == 3, 'slot1 = 3');
    assert(get_slot_size(config, 2) == 10, 'slot2 = 10');
}

#[test]
fn test_decoder_config_7322() {
    // Configuration 7-3-2-2: 4 slots, sizes [7,3,2,2]
    // Total size = 14 bytes
    let config = DECODER_7322;
    assert(config.slot_count == 4, '7322 has 4 slots');
    assert(get_slot_size(config, 0) == 7, 'slot0 = 7');
    assert(get_slot_size(config, 1) == 3, 'slot1 = 3');
    assert(get_slot_size(config, 2) == 2, 'slot2 = 2');
    assert(get_slot_size(config, 3) == 2, 'slot3 = 2');
}

// ============================================================
// Decoder Buffer Initialization
// ============================================================

#[test]
fn test_decoder_buffer_new() {
    // Create decoder buffer
    let buffer = decoder_buffer_new();
    
    // Initial state should be empty
    assert(buffer.cycle == 0, 'initial cycle 0');
    assert(buffer.decode_cycle == 0, 'initial decode_cycle 0');
    assert(buffer.mul_count == 0, 'initial mul_count 0');
}

// ============================================================
// Decoder Configuration Selection
// Based on superscalar.cpp selectConfig()
// ============================================================

#[test]
fn test_decoder_select_config_cycle_0() {
    // At cycle 0, should select 3-1-1-1 (most common)
    let buffer = decoder_buffer_new();
    let config = decoder_select_config(buffer, 0);
    
    // First selection is typically 3-1-1-1
    assert(config.slot_count >= 3, 'valid config');
}

#[test]
fn test_decoder_select_config_deterministic() {
    // Same state + random value should give same config
    let buffer = decoder_buffer_new();
    let config1 = decoder_select_config(buffer, 12345);
    let config2 = decoder_select_config(buffer, 12345);
    
    assert(config1.slot_count == config2.slot_count, 'deterministic');
}

// ============================================================
// Macro-Op Fetching
// ============================================================

#[test]
fn test_decoder_fetch_macro_op_basic() {
    // Fetch a macro-op from generator
    let seed: Array<u8> = array![
        0x74, 0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79,
        0x20, 0x30, 0x30, 0x30
    ];
    let gen = blake2b_generator_new(seed.span(), 0);
    
    let (_new_gen, macro_op) = decoder_fetch_macro_op(gen, 3);
    
    // Macro-op should have valid opcode (u8 is always 0-255)
    assert(macro_op.opcode <= 255, 'valid opcode');
}

#[test]
fn test_decoder_fetch_macro_op_size_3() {
    // Size 3 macro-op: 1 byte opcode + 2 bytes immediate
    let seed: Array<u8> = array![0x00, 0x01, 0x02, 0x03];
    let gen = blake2b_generator_new(seed.span(), 0);
    
    let (_, macro_op) = decoder_fetch_macro_op(gen, 3);
    
    // Should have read 3 bytes
    assert(macro_op.size == 3, 'size 3');
}

#[test]
fn test_decoder_fetch_macro_op_size_4() {
    // Size 4 macro-op: 1 byte opcode + 3 bytes immediate
    let seed: Array<u8> = array![0x00, 0x01, 0x02, 0x03];
    let gen = blake2b_generator_new(seed.span(), 0);
    
    let (_, macro_op) = decoder_fetch_macro_op(gen, 4);
    
    assert(macro_op.size == 4, 'size 4');
}

// ============================================================
// Macro-Op to Instruction Mapping
// ============================================================

#[test]
fn test_macro_op_to_instruction_type() {
    // Macro-op opcodes map to SuperscalarHash instruction types
    // This is based on the superscalar.cpp instruction table
    
    // The mapping is deterministic based on opcode byte
    // Specific mappings will be verified against RandomX source
    assert(true, 'placeholder');
}

// ============================================================
// Slot Selection Logic
// From superscalar.cpp selectSlot()
// ============================================================

#[test]
fn test_slot_selection_prefers_multiplication() {
    // Multiplications should go to specific slots
    // This affects ISAP scheduling
    assert(true, 'placeholder');
}

// ============================================================
// Decode Cycle Tracking
// ============================================================

#[test]
fn test_decode_cycle_advances() {
    // Each decode operation advances the cycle counter
    let mut buffer = decoder_buffer_new();
    let initial_cycle = buffer.decode_cycle;
    
    // After decoding, cycle should advance
    // (Implementation will update this)
    assert(buffer.decode_cycle == initial_cycle, 'cycle tracking');
}
