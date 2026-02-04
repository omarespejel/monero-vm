// ============================================================
// Decoder Buffer State Machine for SuperscalarHash
// ============================================================
//
// Source: RandomX superscalar.cpp lines 200-400
// Reference: https://github.com/tevador/RandomX/blob/master/src/superscalar.cpp
//
// The decoder selects one of four configurations per decode cycle:
// - 3-1-1-1: 4 slots totaling 6 bytes (most common)
// - 4-4-4-4: 4 slots totaling 16 bytes
// - 3-3-10:  3 slots totaling 16 bytes (IMUL_RCP uses slot 2)
// - 7-3-2-2: 4 slots totaling 14 bytes
//
// Each slot size determines the macro-op that can be placed there.

use super::blake2b::{Blake2bGenerator, blake2b_generator_get_byte};

// ============================================================
// Decoder Configuration Structure
// Using individual fields since Cairo fixed arrays don't support indexing
// ============================================================

#[derive(Copy, Drop)]
pub struct DecoderConfig {
    pub slot_count: u8,        // Number of slots (3 or 4)
    pub slot0: u8,             // Size of slot 0
    pub slot1: u8,             // Size of slot 1
    pub slot2: u8,             // Size of slot 2
    pub slot3: u8,             // Size of slot 3 (0 if only 3 slots)
    pub total_size: u8,        // Total bytes decoded
}

/// Get slot size by index
pub fn get_slot_size(config: DecoderConfig, index: u8) -> u8 {
    match index {
        0 => config.slot0,
        1 => config.slot1,
        2 => config.slot2,
        3 => config.slot3,
        _ => 0,
    }
}

// ============================================================
// Decoder Configurations (from superscalar.cpp)
// ============================================================

/// 3-1-1-1 configuration: most common, 4 slots
pub const DECODER_3111: DecoderConfig = DecoderConfig {
    slot_count: 4,
    slot0: 3, slot1: 1, slot2: 1, slot3: 1,
    total_size: 6,
};

/// 4-4-4-4 configuration: 4 equal slots
pub const DECODER_4444: DecoderConfig = DecoderConfig {
    slot_count: 4,
    slot0: 4, slot1: 4, slot2: 4, slot3: 4,
    total_size: 16,
};

/// 3-3-10 configuration: for IMUL_RCP in slot 2
pub const DECODER_3310: DecoderConfig = DecoderConfig {
    slot_count: 3,
    slot0: 3, slot1: 3, slot2: 10, slot3: 0,
    total_size: 16,
};

/// 7-3-2-2 configuration: mixed sizes
pub const DECODER_7322: DecoderConfig = DecoderConfig {
    slot_count: 4,
    slot0: 7, slot1: 3, slot2: 2, slot3: 2,
    total_size: 14,
};

// ============================================================
// Macro-Op Structure
// ============================================================

#[derive(Copy, Drop)]
pub struct MacroOp {
    pub opcode: u8,       // Instruction opcode byte
    pub imm8: u8,         // 8-bit immediate (if present)
    pub imm16: u16,       // 16-bit immediate (if present)
    pub imm32: u32,       // 32-bit immediate (for IMUL_RCP)
    pub size: u8,         // Total size in bytes
}

// ============================================================
// Decoder Buffer State
// ============================================================

#[derive(Copy, Drop)]
pub struct DecoderBuffer {
    pub cycle: u32,           // Current execution cycle
    pub decode_cycle: u32,    // Current decode cycle
    pub mul_count: u32,       // Number of multiplications scheduled
    pub config_index: u8,     // Current configuration index
}

// ============================================================
// Decoder Functions
// ============================================================

/// Create new decoder buffer in initial state
pub fn decoder_buffer_new() -> DecoderBuffer {
    DecoderBuffer {
        cycle: 0,
        decode_cycle: 0,
        mul_count: 0,
        config_index: 0,
    }
}

/// Select decoder configuration based on state and random value
/// From superscalar.cpp selectConfig()
pub fn decoder_select_config(buffer: DecoderBuffer, random_value: u32) -> DecoderConfig {
    // Configuration selection is based on the current state and randomness
    // The selection follows specific rules from RandomX:
    // 
    // From superscalar.cpp:
    // - If previous was 3-1-1-1, can select any
    // - If previous was 4-4-4-4, prefer 3-1-1-1 or 3-3-10
    // - If need IMUL_RCP, must use 3-3-10 (slot 2 is size 10)
    
    // Simple selection based on random value mod 4
    let selection = random_value % 4;
    
    match selection {
        0 => DECODER_3111,
        1 => DECODER_4444,
        2 => DECODER_3310,
        3 => DECODER_7322,
        _ => DECODER_3111, // fallback
    }
}

/// Fetch a macro-op from the generator with specified size
pub fn decoder_fetch_macro_op(
    gen: Blake2bGenerator,
    size: u8
) -> (Blake2bGenerator, MacroOp) {
    // Read bytes from generator based on size
    let (gen1, opcode) = blake2b_generator_get_byte(gen);
    
    if size == 1 {
        return (gen1, MacroOp {
            opcode: opcode,
            imm8: 0,
            imm16: 0,
            imm32: 0,
            size: 1,
        });
    }
    
    let (gen2, b1) = blake2b_generator_get_byte(gen1);
    
    if size == 2 {
        return (gen2, MacroOp {
            opcode: opcode,
            imm8: b1,
            imm16: 0,
            imm32: 0,
            size: 2,
        });
    }
    
    let (gen3, b2) = blake2b_generator_get_byte(gen2);
    
    if size == 3 {
        let imm16: u16 = b1.into() + b2.into() * 256;
        return (gen3, MacroOp {
            opcode: opcode,
            imm8: 0,
            imm16: imm16,
            imm32: 0,
            size: 3,
        });
    }
    
    let (gen4, b3) = blake2b_generator_get_byte(gen3);
    
    if size == 4 {
        let imm32: u32 = b1.into() + b2.into() * 256 + b3.into() * 65536;
        return (gen4, MacroOp {
            opcode: opcode,
            imm8: 0,
            imm16: 0,
            imm32: imm32,
            size: 4,
        });
    }
    
    // For sizes 5-10, continue reading bytes
    // Size 7 and 10 are used for specific instructions
    let mut current_gen = gen4;
    let mut imm32: u32 = b1.into() + b2.into() * 256 + b3.into() * 65536;
    
    if size >= 5 {
        let (g5, b4) = blake2b_generator_get_byte(current_gen);
        imm32 = imm32 + b4.into() * 16777216;
        current_gen = g5;
    }
    
    // For sizes > 5, we've read all we need for imm32
    // Additional bytes are consumed but not used for immediate
    let mut remaining = size - 5;
    loop {
        if remaining == 0 {
            break;
        }
        let (new_gen, _) = blake2b_generator_get_byte(current_gen);
        current_gen = new_gen;
        remaining -= 1;
    }
    
    (current_gen, MacroOp {
        opcode: opcode,
        imm8: 0,
        imm16: 0,
        imm32: imm32,
        size: size,
    })
}

// ============================================================
// Macro-Op to Instruction Type Mapping
// From superscalar.cpp instruction tables
// ============================================================

/// Instruction slots that can be scheduled
#[derive(Copy, Drop, PartialEq)]
pub enum SlotType {
    Slot3,    // 3-byte macro-op slot
    Slot4,    // 4-byte macro-op slot  
    Slot7,    // 7-byte macro-op slot
    Slot10,   // 10-byte macro-op slot (IMUL_RCP only)
}

/// Determine slot type from size
pub fn get_slot_type(size: u8) -> SlotType {
    // Use if/else for non-sequential values (Cairo 2.11 compatibility)
    if size <= 3 {
        SlotType::Slot3  // 1-3 byte ops go in 3-byte slots
    } else if size == 4 {
        SlotType::Slot4
    } else if size == 7 {
        SlotType::Slot7
    } else if size == 10 {
        SlotType::Slot10
    } else {
        SlotType::Slot3  // default
    }
}

// ============================================================
// Decoder Cycle Management
// ============================================================

/// Advance decoder to next cycle
pub fn decoder_advance_cycle(buffer: DecoderBuffer) -> DecoderBuffer {
    DecoderBuffer {
        cycle: buffer.cycle + 1,
        decode_cycle: buffer.decode_cycle + 1,
        mul_count: buffer.mul_count,
        config_index: buffer.config_index,
    }
}

/// Increment multiplication count
pub fn decoder_add_multiplication(buffer: DecoderBuffer) -> DecoderBuffer {
    DecoderBuffer {
        cycle: buffer.cycle,
        decode_cycle: buffer.decode_cycle,
        mul_count: buffer.mul_count + 1,
        config_index: buffer.config_index,
    }
}
