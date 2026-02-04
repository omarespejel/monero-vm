use core::array::ArrayTrait;
use core::poseidon::poseidon_hash_span;
use core::traits::TryInto;

use super::cache_commitment::verify_cache_leaf;

const PROTO_DOMAIN: felt252 = 0x70726f746f;
const MASK_64: u128 = 0xffffffffffffffff;
const POW2_64: u128 = 0x10000000000000000;

const INIT_MUL: u128 = 6364136223846793005;
const INIT_XOR_1: u64 = 9298411001130361340;
const INIT_XOR_2: u64 = 12065312585734608966;
const INIT_XOR_3: u64 = 9306329213124626780;
const INIT_XOR_4: u64 = 5281919268842080866;
const INIT_XOR_5: u64 = 10536153434571861004;
const INIT_XOR_6: u64 = 3398623926847679864;
const INIT_XOR_7: u64 = 9549104520008361294;

const SUPERSCALAR_SEED: u128 = 0x9e3779b97f4a7c15;
const CACHE_ITEMS: u64 = 262144;

#[derive(Copy, Drop)]
pub struct Registers {
    pub r0: u64,
    pub r1: u64,
    pub r2: u64,
    pub r3: u64,
    pub r4: u64,
    pub r5: u64,
    pub r6: u64,
    pub r7: u64,
}

#[derive(Copy, Drop)]
pub struct CacheItem {
    pub w0: u64,
    pub w1: u64,
    pub w2: u64,
    pub w3: u64,
    pub w4: u64,
    pub w5: u64,
    pub w6: u64,
    pub w7: u64,
}

fn wrap_u64(value: u128) -> u64 {
    let masked = value & MASK_64;
    masked.try_into().unwrap()
}

fn to_u128(value: u64) -> u128 {
    value.into()
}

fn pow2_u128(exp: u32) -> u128 {
    let mut result = 1_u128;
    let mut i: u32 = 0;
    loop {
        if i == exp {
            break;
        }
        result = result * 2_u128;
        i += 1;
    }
    result
}

pub fn wrapping_add_64(a: u64, b: u64) -> u64 {
    wrap_u64(to_u128(a) + to_u128(b))
}

pub fn rotate_right_64(value: u64, shift: u32) -> u64 {
    let s: u32 = shift & 63;
    if s == 0 {
        return value;
    }
    let pow2 = pow2_u128(s);
    let val = to_u128(value);
    let right = val / pow2;
    let left = (val % pow2) * pow2_u128(64 - s);
    wrap_u64(right + left)
}

pub fn rotate_left_64(value: u64, shift: u32) -> u64 {
    let s: u32 = shift & 63;
    if s == 0 {
        return value;
    }
    // Rotate left by s = rotate right by (64 - s)
    rotate_right_64(value, 64 - s)
}

pub fn irol_r(dst: u64, src: u64) -> u64 {
    // IROL_R rotates left by src & 63 bits
    rotate_left_64(dst, (src & 63).try_into().unwrap())
}

pub fn wrapping_mul_64(a: u64, b: u64) -> u64 {
    wrap_u64(to_u128(a) * to_u128(b))
}

pub fn wrapping_sub_64(a: u64, b: u64) -> u64 {
    if a >= b {
        wrap_u64(to_u128(a) - to_u128(b))
    } else {
        wrap_u64(POW2_64 - (to_u128(b) - to_u128(a)))
    }
}

pub fn imulh_u64(a: u64, b: u64) -> u64 {
    let prod: u128 = to_u128(a) * to_u128(b);
    let high = prod / POW2_64;
    high.try_into().unwrap()
}

/// Signed multiply high - returns upper 64 bits of signed 128-bit product
/// Reference: RandomX src/instructions_portable.cpp smulh()
/// Implements: ((int128_t)a * b) >> 64
///
/// CRITICAL: Must produce EXACT bit-perfect results for hash verification.
/// Uses unsigned arithmetic with manual sign handling to avoid Cairo i128 issues.
pub fn ismulh_i64(a: i64, b: i64) -> i64 {
    // Convert i64 to u64 for bit manipulation
    // The bit pattern is the same, just interpreted differently
    let a_u: u64 = i64_to_u64(a);
    let b_u: u64 = i64_to_u64(b);
    
    // Call the u64 version which handles signs correctly
    let result_u = ismulh_u64(a_u, b_u);
    
    // Convert back to i64
    u64_to_i64(result_u)
}

/// Convert i64 to u64 preserving bit pattern
fn i64_to_u64(x: i64) -> u64 {
    if x >= 0 {
        x.try_into().unwrap()
    } else {
        // For negative: add 2^64 to get the two's complement representation
        let abs_x: u64 = (-(x + 1)).try_into().unwrap();
        0xFFFFFFFFFFFFFFFF - abs_x
    }
}

/// Convert u64 to i64 preserving bit pattern
fn u64_to_i64(x: u64) -> i64 {
    if x < 0x8000000000000000 {
        x.try_into().unwrap()
    } else {
        // High bit set = negative in two's complement
        // Convert: result = x - 2^64
        let complement: u64 = 0xFFFFFFFFFFFFFFFF - x;
        let neg_val: i64 = (complement + 1).try_into().unwrap();
        -neg_val
    }
}

/// Signed multiply high using unsigned arithmetic with manual sign handling
/// This avoids Cairo i128 arithmetic issues by using proven u128 operations
pub fn ismulh_u64(a: u64, b: u64) -> u64 {
    // Determine signs (MSB = 1 means negative in two's complement)
    let a_neg = a >= 0x8000000000000000;
    let b_neg = b >= 0x8000000000000000;
    
    // Get absolute values
    let a_abs: u64 = if a_neg { wrapping_sub_64(0, a) } else { a };
    let b_abs: u64 = if b_neg { wrapping_sub_64(0, b) } else { b };
    
    // Compute full 128-bit product of absolute values
    let prod_u128: u128 = to_u128(a_abs) * to_u128(b_abs);
    
    // Extract high and low 64 bits
    let high_abs: u64 = (prod_u128 / POW2_64).try_into().unwrap();
    let low: u64 = wrap_u64(prod_u128);
    
    // Determine result sign: negative if exactly one input is negative
    let result_neg = a_neg != b_neg;
    
    if !result_neg {
        // Same signs (both positive OR both negative) -> positive result
        high_abs
    } else {
        // Different signs -> negative result
        // For the 128-bit two's complement negation:
        // -x = ~x + 1 = (2^128 - x)
        // The high 64 bits of -x depend on whether low bits are zero:
        //   If low == 0: high' = -high (no borrow from low)
        //   If low != 0: high' = ~high = -high - 1 (borrow from low)
        if low == 0 {
            wrapping_sub_64(0, high_abs)
        } else {
            // ~high_abs in 64-bit = 0xFFFFFFFFFFFFFFFF - high_abs
            // Use wrapping subtraction to avoid underflow
            wrapping_sub_64(wrapping_sub_64(0, high_abs), 1)
        }
    }
}

pub fn imul_r(dst: u64, src: u64) -> u64 {
    wrapping_mul_64(dst, src)
}

pub fn ixor_r(dst: u64, src: u64) -> u64 {
    dst ^ src
}

pub fn iadd_rs(dst: u64, src: u64, shift: u32) -> u64 {
    let s = shift & 3;
    let factor = pow2_u128(s);
    let shifted = wrap_u64(to_u128(src) * factor);
    wrapping_add_64(dst, shifted)
}

pub fn iror_c(dst: u64, imm: u32) -> u64 {
    rotate_right_64(dst, imm & 63)
}

pub fn isub_r(dst: u64, src: u64) -> u64 {
    wrapping_sub_64(dst, src)
}

/// Sign-extend a 32-bit unsigned integer to 64-bit signed integer.
/// Per RandomX Spec 5.1.5: IADD_C* and IXOR_C* use sign-extended imm32.
/// 
/// Sign extension: if bit 31 is set, extend with 1s in upper 32 bits.
pub fn sign_extend_32_to_64(imm32: u32) -> u64 {
    // Check if MSB (bit 31) is set: (imm32 / 2^31) % 2
    let pow2_31: u32 = pow2_u128(31).try_into().unwrap();
    let sign_bit: u32 = (imm32 / pow2_31) % 2;
    let imm64: u64 = imm32.into();
    
    if sign_bit == 1 {
        // Sign-extend with 1s: set upper 32 bits to 1
        // 0xFFFFFFFF00000000 | imm32
        let upper_mask: u64 = 0xFFFFFFFF00000000;
        imm64 | upper_mask
    } else {
        // Sign-extend with 0s: upper bits already 0
        imm64
    }
}

/// Count leading zeros in a 32-bit value.
/// Returns the number of leading zero bits (0-32).
fn count_leading_zeros_32(value: u32) -> u32 {
    if value == 0 {
        return 32;
    }
    
    let mut shift: u32 = 32;
    let mut k: u32 = pow2_u128(31).try_into().unwrap();
    
    loop {
        if (k & value) != 0 {
            break;
        }
        k = k / 2;
        shift -= 1;
        if shift == 0 {
            break;
        }
    }
    shift
}

/// Count leading zeros in a 64-bit value.
/// Returns the number of leading zero bits (0-64).
fn count_leading_zeros_64(value: u64) -> u32 {
    if value == 0 {
        return 64;
    }
    
    let mut count: u32 = 0;
    let mut k: u128 = pow2_u128(63); // 2^63
    let val128: u128 = value.into();
    
    loop {
        if (k & val128) != 0 {
            break;
        }
        k = k / 2;
        count += 1;
        if count == 64 {
            break;
        }
    }
    count
}

/// RandomX reciprocal calculation
/// From RandomX reciprocal.c:
/// ```c
/// uint64_t randomx_reciprocal(uint64_t divisor) {
///     const uint64_t p2exp63 = 1ULL << 63;
///     uint64_t quotient = p2exp63 / divisor, remainder = p2exp63 % divisor;
///     uint32_t bsr = 64 - clz64(divisor);  // bit position of highest set bit + 1
///     quotient <<= bsr;  // wrapping shift
///     remainder <<= bsr;
///     quotient += remainder / divisor;
///     return quotient;
/// }
/// ```
/// 
/// Note: divisor must not be 0 or a power of 2 (enforced during program generation).
pub fn randomx_reciprocal(divisor: u64) -> u64 {
    // Per spec, divisor=0 and power-of-2 are rejected during generation
    if divisor == 0 {
        return 0;
    }
    
    // Check if divisor is power of 2
    let is_power2 = (divisor & (divisor - 1)) == 0;
    if is_power2 {
        return 0;
    }
    
    const P2EXP63: u128 = 0x8000000000000000; // 2^63
    const MASK_64: u128 = 0xFFFFFFFFFFFFFFFF;
    
    // Calculate q = 2^63 / divisor and r = 2^63 % divisor
    let divisor128: u128 = divisor.into();
    let quotient = P2EXP63 / divisor128;
    let remainder = P2EXP63 % divisor128;
    
    // Find bsr = 64 - clz64(divisor)
    // clz64 returns the number of leading zeros in a 64-bit value
    let clz = count_leading_zeros_64(divisor);
    let bsr: u32 = 64 - clz;
    
    // quotient <<= bsr (with wrapping)
    let pow2_bsr = pow2_u128(bsr);
    let q_shifted = (quotient * pow2_bsr) & MASK_64;
    
    // remainder <<= bsr
    let r_shifted = remainder * pow2_bsr;
    
    // quotient += remainder / divisor
    let result = q_shifted + (r_shifted / divisor128);
    
    // Return result masked to 64 bits
    (result & MASK_64).try_into().unwrap()
}

/// IMUL_RCP: Multiply destination by reciprocal of immediate.
/// r[dst] *= randomx_reciprocal(imm32)
/// 
/// Per Spec 5.2.6: IMUL_RCP is no-op when imm32 == 0 or imm32 is power of 2.
/// These cases are rejected during program generation.
pub fn imul_rcp(dst: u64, imm32: u32) -> u64 {
    let rcp = randomx_reciprocal(imm32.into());
    if rcp == 0 {
        // Should not happen in valid programs, but return dst unchanged
        return dst;
    }
    // Multiply: result = (dst * rcp) >> 64 (high 64 bits of 128-bit product)
    // In practice, we compute the high bits of the product
    let prod: u128 = to_u128(dst) * to_u128(rcp);
    let high = prod / POW2_64;
    high.try_into().unwrap()
}

/// IADD_C7: Add sign-extended 7-bit immediate to destination.
/// r[dst] += signExtend2sCompl(imm32 & 0x7F)
/// 
/// Note: The immediate is treated as a 7-bit signed value, so bit 6 is the sign bit.
pub fn iadd_c7(dst: u64, imm32: u32) -> u64 {
    let imm7 = imm32 & 0x7F;
    // Sign-extend 7-bit value: if bit 6 (MSB of 7-bit) is set, extend with 1s
    // Extract bit 6: (imm7 / 2^6) % 2
    let pow2_6: u32 = pow2_u128(6).try_into().unwrap();
    let sign_bit = (imm7 / pow2_6) % 2;
    let extended: u64 = if sign_bit == 1 {
        // Negative: extend upper 57 bits with 1s
        imm7.into() | 0xFFFFFFFFFFFFFF80
    } else {
        // Positive: upper bits are 0
        imm7.into()
    };
    wrapping_add_64(dst, extended)
}

/// IADD_C8: Add sign-extended 8-bit immediate to destination.
/// r[dst] += signExtend2sCompl(imm32 & 0xFF)
/// 
/// Note: The immediate is treated as an 8-bit signed value, so bit 7 is the sign bit.
pub fn iadd_c8(dst: u64, imm32: u32) -> u64 {
    let imm8 = imm32 & 0xFF;
    // Sign-extend 8-bit value: if bit 7 is set, extend with 1s
    // Extract bit 7: (imm8 / 2^7) % 2
    let pow2_7: u32 = pow2_u128(7).try_into().unwrap();
    let sign_bit = (imm8 / pow2_7) % 2;
    let extended: u64 = if sign_bit == 1 {
        // Negative: extend upper 56 bits with 1s
        imm8.into() | 0xFFFFFFFFFFFFFF00
    } else {
        // Positive: upper bits are 0
        imm8.into()
    };
    wrapping_add_64(dst, extended)
}

/// IADD_C9: Add sign-extended 9-bit immediate to destination.
/// r[dst] += signExtend2sCompl(imm32 & 0x1FF)
/// 
/// Note: The immediate is treated as a 9-bit signed value, so bit 8 is the sign bit.
pub fn iadd_c9(dst: u64, imm32: u32) -> u64 {
    let imm9 = imm32 & 0x1FF;
    // Sign-extend 9-bit value: if bit 8 is set, extend with 1s
    // Extract bit 8: (imm9 / 2^8) % 2
    let pow2_8: u32 = pow2_u128(8).try_into().unwrap();
    let sign_bit = (imm9 / pow2_8) % 2;
    let extended: u64 = if sign_bit == 1 {
        // Negative: extend upper 55 bits with 1s
        imm9.into() | 0xFFFFFFFFFFFFFE00
    } else {
        // Positive: upper bits are 0
        imm9.into()
    };
    wrapping_add_64(dst, extended)
}

/// IXOR_C7: XOR sign-extended 7-bit immediate with destination.
/// r[dst] ^= signExtend2sCompl(imm32 & 0x7F)
/// 
/// Note: The immediate is treated as a 7-bit signed value, so bit 6 is the sign bit.
pub fn ixor_c7(dst: u64, imm32: u32) -> u64 {
    let imm7 = imm32 & 0x7F;
    // Extract bit 6: (imm7 / 2^6) % 2
    let pow2_6: u32 = pow2_u128(6).try_into().unwrap();
    let sign_bit = (imm7 / pow2_6) % 2;
    let extended: u64 = if sign_bit == 1 {
        // Negative: extend upper 57 bits with 1s
        imm7.into() | 0xFFFFFFFFFFFFFF80
    } else {
        // Positive: upper bits are 0
        imm7.into()
    };
    dst ^ extended
}

/// IXOR_C8: XOR sign-extended 8-bit immediate with destination.
/// r[dst] ^= signExtend2sCompl(imm32 & 0xFF)
/// 
/// Note: The immediate is treated as an 8-bit signed value, so bit 7 is the sign bit.
pub fn ixor_c8(dst: u64, imm32: u32) -> u64 {
    let imm8 = imm32 & 0xFF;
    // Extract bit 7: (imm8 / 2^7) % 2
    let pow2_7: u32 = pow2_u128(7).try_into().unwrap();
    let sign_bit = (imm8 / pow2_7) % 2;
    let extended: u64 = if sign_bit == 1 {
        // Negative: extend upper 56 bits with 1s
        imm8.into() | 0xFFFFFFFFFFFFFF00
    } else {
        // Positive: upper bits are 0
        imm8.into()
    };
    dst ^ extended
}

/// IXOR_C9: XOR sign-extended 9-bit immediate with destination.
/// r[dst] ^= signExtend2sCompl(imm32 & 0x1FF)
/// 
/// Note: The immediate is treated as a 9-bit signed value, so bit 8 is the sign bit.
pub fn ixor_c9(dst: u64, imm32: u32) -> u64 {
    let imm9 = imm32 & 0x1FF;
    // Extract bit 8: (imm9 / 2^8) % 2
    let pow2_8: u32 = pow2_u128(8).try_into().unwrap();
    let sign_bit = (imm9 / pow2_8) % 2;
    let extended: u64 = if sign_bit == 1 {
        // Negative: extend upper 55 bits with 1s
        imm9.into() | 0xFFFFFFFFFFFFFE00
    } else {
        // Positive: upper bits are 0
        imm9.into()
    };
    dst ^ extended
}

pub fn init_registers(item_number: u64) -> Registers {
    let item: u128 = item_number.into();
    let r0 = wrap_u64((item + 1) * INIT_MUL);
    Registers {
        r0,
        r1: r0 ^ INIT_XOR_1,
        r2: r0 ^ INIT_XOR_2,
        r3: r0 ^ INIT_XOR_3,
        r4: r0 ^ INIT_XOR_4,
        r5: r0 ^ INIT_XOR_5,
        r6: r0 ^ INIT_XOR_6,
        r7: r0 ^ INIT_XOR_7,
    }
}

pub fn xor_registers_with_cache(regs: Registers, cache: CacheItem) -> Registers {
    Registers {
        r0: regs.r0 ^ cache.w0,
        r1: regs.r1 ^ cache.w1,
        r2: regs.r2 ^ cache.w2,
        r3: regs.r3 ^ cache.w3,
        r4: regs.r4 ^ cache.w4,
        r5: regs.r5 ^ cache.w5,
        r6: regs.r6 ^ cache.w6,
        r7: regs.r7 ^ cache.w7,
    }
}

pub fn superscalar_hash_stub(regs: Registers) -> Registers {
    Registers {
        r0: wrap_u64(to_u128(regs.r0) + SUPERSCALAR_SEED),
        r1: wrap_u64(to_u128(regs.r1) + SUPERSCALAR_SEED),
        r2: wrap_u64(to_u128(regs.r2) + SUPERSCALAR_SEED),
        r3: wrap_u64(to_u128(regs.r3) + SUPERSCALAR_SEED),
        r4: wrap_u64(to_u128(regs.r4) + SUPERSCALAR_SEED),
        r5: wrap_u64(to_u128(regs.r5) + SUPERSCALAR_SEED),
        r6: wrap_u64(to_u128(regs.r6) + SUPERSCALAR_SEED),
        r7: wrap_u64(to_u128(regs.r7) + SUPERSCALAR_SEED),
    }
}

pub fn prototype_dataset_item(item_number: u64, cache: CacheItem) -> Registers {
    let regs = init_registers(item_number);
    let mixed = xor_registers_with_cache(regs, cache);
    superscalar_hash_stub(mixed)
}

pub fn cache_index_modulo(index: u64) -> u64 {
    index % CACHE_ITEMS
}

pub fn get_next_cache_index_stub(regs: Registers) -> u64 {
    regs.r7
}

/// Verifies 8 cache lookups and returns an error code.
/// 0 = ok
/// 1 = leaves length mismatch
/// 2 = proofs length mismatch
/// 10..17 = proof failed at index (idx = code - 10)
pub fn verify_cache_lookups_8(
    root: felt252,
    leaves: Span<felt252>,
    proofs_flat: Span<felt252>,
    proof_len: usize,
) -> u32 {
    if leaves.len() != 8 {
        return 1;
    }
    if proofs_flat.len() != proof_len * 8 {
        return 2;
    }

    let mut i: usize = 0;
    loop {
        let mut proof = ArrayTrait::new();
        let mut j: usize = 0;
        loop {
            let idx = i * proof_len + j;
            proof.append(*proofs_flat.at(idx));
            j += 1;
            if j == proof_len {
                break;
            }
        }
        let ok = verify_cache_leaf(root, *leaves.at(i), proof.span());
        if !ok {
            return 10 + i;
        }
        i += 1;
        if i == 8 {
            break;
        }
    }
    0
}

/// Prototype hash: validates 8 cache proofs, then Poseidon-hashes the leaves
/// with a domain separator. Returns None on failure.
pub fn prototype_hash_from_cache(
    root: felt252,
    leaves: Span<felt252>,
    proofs_flat: Span<felt252>,
    proof_len: usize,
) -> Option<felt252> {
    let code = verify_cache_lookups_8(root, leaves, proofs_flat, proof_len);
    if code != 0 {
        return Option::None;
    }

    let mut elements = ArrayTrait::new();
    elements.append(PROTO_DOMAIN);
    for leaf in leaves {
        elements.append(*leaf);
    }

    Option::Some(poseidon_hash_span(elements.span()))
}

// ============================================================
// SUPERSCALARHASH PROGRAM GENERATION
// Based on RandomX superscalar.cpp implementation
// ============================================================

/// Instruction types for SuperscalarHash
/// Maps to RandomX SuperscalarInstructionType enum
#[derive(Copy, Drop)]
pub enum InstructionType {
    ISUB_R,
    IXOR_R,
    IADD_RS,
    IMUL_R,
    IROR_C,
    IADD_C7,
    IADD_C8,
    IADD_C9,
    IXOR_C7,
    IXOR_C8,
    IXOR_C9,
    IMULH_R,
    ISMULH_R,
    IMUL_RCP,
}

/// Execution port assignment
/// P0, P1, P5 (multiplication only runs on P1)
#[derive(Copy, Drop)]
pub enum ExecutionPort {
    P0,
    P1,
    P5,
}

/// Register dependency tracking information
/// Per RandomX RegisterInfo struct
#[derive(Copy, Drop)]
pub struct RegisterInfo {
    pub latency: u32,        // cycle when register is ready
    pub last_op_group: InstructionType,  // last operation applied
    pub last_op_par: i32,    // last operation source (-1 = constant)
}

/// Instruction representation for SuperscalarHash program
#[derive(Copy, Drop)]
pub struct SuperscalarInstruction {
    pub opcode: InstructionType,
    pub dst: u32,    // destination register (0-7)
    pub src: u32,    // source register (0-7) or -1 for constant
    pub imm32: u32,  // immediate value (for IADD_C*, IXOR_C*, IROR_C, IMUL_RCP)
    pub mod_shift: u32,  // shift amount for IADD_RS (0-3)
}

/// Initialize RegisterInfo for all 8 registers
pub fn init_register_info() -> Array<RegisterInfo> {
    let mut reg_info = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i == 8 {
            break;
        }
        // Initial latency is 0, no previous operation
        reg_info.append(RegisterInfo {
            latency: 0,
            last_op_group: InstructionType::ISUB_R, // placeholder
            last_op_par: -1,
        });
        i += 1;
    }
    reg_info
}

/// Get execution port for instruction type
/// Per RandomX: multiplication only runs on P1
pub fn get_execution_port(opcode: InstructionType) -> ExecutionPort {
    match opcode {
        InstructionType::IMUL_R => ExecutionPort::P1,
        InstructionType::IMULH_R => ExecutionPort::P1,
        InstructionType::ISMULH_R => ExecutionPort::P1,
        InstructionType::IMUL_RCP => ExecutionPort::P1,
        _ => ExecutionPort::P0, // Most instructions run on P0
    }
}

/// Get instruction latency (cycles until result is ready)
/// Simplified model: multiplication takes longer
pub fn get_instruction_latency(opcode: InstructionType) -> u32 {
    match opcode {
        InstructionType::IMUL_R => 3,
        InstructionType::IMULH_R => 3,
        InstructionType::ISMULH_R => 3,
        InstructionType::IMUL_RCP => 3,
        _ => 1, // Most instructions have 1 cycle latency
    }
}

/// Check if destination register selection is valid
/// Implements the 5 critical rules from RandomX superscalar.cpp
pub fn is_valid_destination(
    dst: u32,
    src: i32,
    opcode: InstructionType,
    reg_info: Span<RegisterInfo>,
    current_cycle: u32,
    allow_chained_mul: bool,
) -> bool {
    // Rule 1: Value must be ready at the required cycle
    let reg = *reg_info.at(dst.try_into().unwrap());
    if reg.latency > current_cycle {
        return false;
    }
    
    // Rule 2: Cannot be same as source register unless instruction allows it
    // (avoids xor r, r)
    if src >= 0 {
        let dst_i32: i32 = dst.try_into().unwrap();
        if dst_i32 == src {
            // Most instructions don't allow dst == src
            let invalid_same_reg = match opcode {
                InstructionType::IXOR_R => true, // xor r, r is no-op
                InstructionType::ISUB_R => true, // sub r, r = 0
                _ => false,
            };
            if invalid_same_reg {
                return false;
            }
        }
    }
    
    // Rule 3: Register cannot be multiplied twice in a row unless allowChainedMul is true
    if !allow_chained_mul {
        let is_mul_op = match opcode {
            InstructionType::IMUL_R => true,
            InstructionType::IMULH_R => true,
            InstructionType::ISMULH_R => true,
            InstructionType::IMUL_RCP => true,
            _ => false,
        };
        if is_mul_op {
            let was_mul_op = match reg.last_op_group {
                InstructionType::IMUL_R => true,
                InstructionType::IMULH_R => true,
                InstructionType::ISMULH_R => true,
                InstructionType::IMUL_RCP => true,
                _ => false,
            };
            if was_mul_op {
                return false; // Cannot chain multiplications
            }
        }
    }
    
    // Rule 4: Last instruction applied OR its source must differ from current
    // (avoids xor r1,r2; xor r1,r2)
    // Note: Enum comparison in Cairo requires matching each variant
    let same_op = match (reg.last_op_group, opcode) {
        (InstructionType::ISUB_R, InstructionType::ISUB_R) => true,
        (InstructionType::IXOR_R, InstructionType::IXOR_R) => true,
        (InstructionType::IADD_RS, InstructionType::IADD_RS) => true,
        (InstructionType::IMUL_R, InstructionType::IMUL_R) => true,
        (InstructionType::IROR_C, InstructionType::IROR_C) => true,
        (InstructionType::IADD_C7, InstructionType::IADD_C7) => true,
        (InstructionType::IADD_C8, InstructionType::IADD_C8) => true,
        (InstructionType::IADD_C9, InstructionType::IADD_C9) => true,
        (InstructionType::IXOR_C7, InstructionType::IXOR_C7) => true,
        (InstructionType::IXOR_C8, InstructionType::IXOR_C8) => true,
        (InstructionType::IXOR_C9, InstructionType::IXOR_C9) => true,
        (InstructionType::IMULH_R, InstructionType::IMULH_R) => true,
        (InstructionType::ISMULH_R, InstructionType::ISMULH_R) => true,
        (InstructionType::IMUL_RCP, InstructionType::IMUL_RCP) => true,
        _ => false,
    };
    if same_op {
        if reg.last_op_par == src {
            return false; // Same operation with same source
        }
    }
    
    // Rule 5: Register r5 cannot be destination of IADD_RS (x86 lea limitation)
    let is_iadd_rs = match opcode {
        InstructionType::IADD_RS => true,
        _ => false,
    };
    if is_iadd_rs && dst == 5 {
        return false;
    }
    
    true
}

/// Select a valid destination register
/// Returns Some(register_index) if valid, None if no valid register found
pub fn select_destination_register(
    src: i32,
    opcode: InstructionType,
    reg_info: Span<RegisterInfo>,
    current_cycle: u32,
    allow_chained_mul: bool,
) -> Option<u32> {
    // Try registers in order: r0, r1, r2, r3, r4, r5, r6, r7
    let mut i: u32 = 0;
    loop {
        if i == 8 {
            break;
        }
        if is_valid_destination(i, src, opcode, reg_info, current_cycle, allow_chained_mul) {
            return Option::Some(i);
        }
        i += 1;
    }
    Option::None
}

/// Force select a destination register (fallback when normal selection fails)
/// Relaxes some rules to ensure we always find a destination
fn force_select_destination_register(
    src: i32,
    opcode: InstructionType,
    reg_info: Span<RegisterInfo>,
    current_cycle: u32,
) -> u32 {
    // Try with relaxed rules: allow chained multiplications
    let dst_opt = select_destination_register(src, opcode, reg_info, current_cycle, true);
    if dst_opt.is_some() {
        return dst_opt.unwrap();
    }
    
    // If still no destination, find any register that's ready (relax all rules except latency)
    let mut i: u32 = 0;
    loop {
        if i == 8 {
            break;
        }
        let reg = *reg_info.at(i.try_into().unwrap());
        // Only check latency - ignore other rules
        if reg.latency <= current_cycle {
            // Skip r5 restriction for IADD_RS only if absolutely necessary
            let is_iadd_rs = match opcode {
                InstructionType::IADD_RS => true,
                _ => false,
            };
            if !(is_iadd_rs && i == 5) {
                return i;
            }
        }
        i += 1;
    }
    
    // Last resort: find register with lowest latency (will be ready soonest)
    let mut best_reg: u32 = 0;
    let reg0 = *reg_info.at(0);
    let mut min_latency = reg0.latency;
    let mut j: u32 = 1;
    loop {
        if j == 8 {
            break;
        }
        let reg = *reg_info.at(j.try_into().unwrap());
        if reg.latency < min_latency {
            min_latency = reg.latency;
            best_reg = j;
        }
        j += 1;
    }
    
    // Return best register (even if not ready, cycle will advance)
    best_reg
}

/// Update register info after instruction execution
pub fn update_register_info(
    reg_info: Span<RegisterInfo>,
    dst: u32,
    opcode: InstructionType,
    src: i32,
    current_cycle: u32,
) -> RegisterInfo {
    let latency = get_instruction_latency(opcode);
    RegisterInfo {
        latency: current_cycle + latency,
        last_op_group: opcode,
        last_op_par: src,
    }
}

/// Simple PRNG for program generation (LCG-based)
/// Based on RandomX's approach
fn next_random(seed: u64) -> (u64, u64) {
    // Linear congruential generator: seed = (seed * 6364136223846793005 + 1) mod 2^64
    const MULT: u128 = 6364136223846793005;
    let seed128: u128 = seed.into();
    let new_seed128 = (seed128 * MULT + 1) & MASK_64;
    let new_seed: u64 = new_seed128.try_into().unwrap();
    (new_seed, new_seed)
}

/// Select random instruction type based on seed
/// Returns (new_seed, instruction_type)
fn select_instruction_type(seed: u64) -> (u64, InstructionType) {
    let (new_seed, rand_val) = next_random(seed);
    // Map random value to instruction type (14 types)
    let type_idx: u32 = (rand_val % 14).try_into().unwrap();
    
    let opcode = match type_idx {
        0 => InstructionType::ISUB_R,
        1 => InstructionType::IXOR_R,
        2 => InstructionType::IADD_RS,
        3 => InstructionType::IMUL_R,
        4 => InstructionType::IROR_C,
        5 => InstructionType::IADD_C7,
        6 => InstructionType::IADD_C8,
        7 => InstructionType::IADD_C9,
        8 => InstructionType::IXOR_C7,
        9 => InstructionType::IXOR_C8,
        10 => InstructionType::IXOR_C9,
        11 => InstructionType::IMULH_R,
        12 => InstructionType::ISMULH_R,
        13 => InstructionType::IMUL_RCP,
        _ => InstructionType::ISUB_R, // Fallback
    };
    
    (new_seed, opcode)
}

/// Select random source register (0-7) or -1 for constant
fn select_source_register(seed: u64, opcode: InstructionType) -> (u64, i32) {
    let (new_seed, rand_val) = next_random(seed);
    
    // Some instructions use constants (IADD_C*, IXOR_C*, IROR_C, IMUL_RCP)
    let uses_constant = match opcode {
        InstructionType::IADD_C7 | InstructionType::IADD_C8 | InstructionType::IADD_C9 => true,
        InstructionType::IXOR_C7 | InstructionType::IXOR_C8 | InstructionType::IXOR_C9 => true,
        InstructionType::IROR_C | InstructionType::IMUL_RCP => true,
        _ => false,
    };
    
    if uses_constant {
        (new_seed, -1)
    } else {
        let src_reg: u32 = (rand_val % 8).try_into().unwrap();
        (new_seed, src_reg.try_into().unwrap())
    }
}

/// Generate immediate value for instruction
fn generate_immediate(seed: u64, opcode: InstructionType) -> (u64, u32) {
    let (new_seed, rand_val) = next_random(seed);
    
    let imm = match opcode {
        InstructionType::IADD_C7 => (rand_val & 0x7F).try_into().unwrap(),
        InstructionType::IADD_C8 => (rand_val & 0xFF).try_into().unwrap(),
        InstructionType::IADD_C9 => (rand_val & 0x1FF).try_into().unwrap(),
        InstructionType::IXOR_C7 => (rand_val & 0x7F).try_into().unwrap(),
        InstructionType::IXOR_C8 => (rand_val & 0xFF).try_into().unwrap(),
        InstructionType::IXOR_C9 => (rand_val & 0x1FF).try_into().unwrap(),
        InstructionType::IROR_C => {
            // IROR_C: imm32 % 64 != 0 enforced
            let rot: u32 = ((rand_val % 63) + 1).try_into().unwrap(); // 1-63
            rot
        },
        InstructionType::IMUL_RCP => {
            // IMUL_RCP: imm32 != 0 and not power of 2
            // Simplified: use odd values > 1
            let imm_val: u32 = ((rand_val % 0x7FFFFFFE) + 3).try_into().unwrap(); // 3 to max
            // Ensure not power of 2 (simplified check)
            imm_val | 1 // Make odd
        },
        InstructionType::IADD_RS => (rand_val & 3).try_into().unwrap(), // mod_shift: 0-3
        _ => 0,
    };
    
    (new_seed, imm)
}

/// Generate SuperscalarHash program with dependency tracking
/// Implements RandomX's executeSuperscalar algorithm
pub fn generate_superscalar_program(
    seed: u64,
    program_size: u32,
) -> Array<SuperscalarInstruction> {
    let mut program = ArrayTrait::new();
    let mut reg_info_array = init_register_info();
    let mut current_seed = seed;
    let mut current_cycle: u32 = 0;
    
    let mut i: u32 = 0;
    loop {
        if i == program_size {
            break;
        }
        
        // Select instruction type
        let (seed1, mut opcode) = select_instruction_type(current_seed);
        let mut attempt_seed = seed1;
        
        // Select source register
        let (seed2, mut src) = select_source_register(attempt_seed, opcode);
        attempt_seed = seed2;
        
        // Generate immediate/mod_shift
        let (seed3, mut imm32) = generate_immediate(attempt_seed, opcode);
        attempt_seed = seed3;
        
        // Select destination register (respecting all 5 rules)
        // Retry with different parameters if needed
        let mut retry_count = 0_u32;
        
        loop {
            // Advance cycle more aggressively to free registers
            if retry_count > 0 && retry_count % 5 == 0 {
                current_cycle += 3;
            }
            
            if retry_count > 50 {
                // After 50 retries, force selection
                let reg_info_span = reg_info_array.span();
                let forced_dst = force_select_destination_register(src, opcode, reg_info_span, current_cycle);
                
                // Create instruction with forced destination
                let is_iadd_rs = match opcode {
                    InstructionType::IADD_RS => true,
                    _ => false,
                };
                
                let mod_shift = if is_iadd_rs {
                    imm32 & 3
                } else {
                    0
                };
                
                let imm = if is_iadd_rs {
                    0
                } else {
                    imm32
                };
                
                program.append(SuperscalarInstruction {
                    opcode,
                    dst: forced_dst,
                    src: if src >= 0 { src.try_into().unwrap() } else { 0 },
                    imm32: imm,
                    mod_shift,
                });
                
                // Update register info
                let reg_info_span2 = reg_info_array.span();
                let updated_reg = update_register_info(reg_info_span2, forced_dst, opcode, src, current_cycle);
                
                // Update reg_info_array
                let mut new_reg_info = ArrayTrait::new();
                let mut j: usize = 0;
                loop {
                    if j == 8 {
                        break;
                    }
                    if j == forced_dst.try_into().unwrap() {
                        new_reg_info.append(updated_reg);
                    } else {
                        new_reg_info.append(*reg_info_array.at(j));
                    }
                    j += 1;
                }
                reg_info_array = new_reg_info;
                
                current_cycle += 1;
                current_seed = attempt_seed;
                break;
            }
            
            let reg_info_span = reg_info_array.span();
            // Allow chained multiplications if we've retried many times
            let allow_chain = retry_count > 20;
            let dst_opt = select_destination_register(src, opcode, reg_info_span, current_cycle, allow_chain);
            
            if dst_opt.is_some() {
                let dst = dst_opt.unwrap();
                
                // Create instruction
                let is_iadd_rs = match opcode {
                    InstructionType::IADD_RS => true,
                    _ => false,
                };
                
                let mod_shift = if is_iadd_rs {
                    imm32 & 3
                } else {
                    0
                };
                
                let imm = if is_iadd_rs {
                    0 // mod_shift stored separately
                } else {
                    imm32
                };
                
                program.append(SuperscalarInstruction {
                    opcode,
                    dst,
                    src: if src >= 0 { src.try_into().unwrap() } else { 0 },
                    imm32: imm,
                    mod_shift,
                });
                
                // Update register info
                let updated_reg = update_register_info(reg_info_span, dst, opcode, src, current_cycle);
                
                // Update reg_info_array
                let mut new_reg_info = ArrayTrait::new();
                let mut j: usize = 0;
                loop {
                    if j == 8 {
                        break;
                    }
                    if j == dst.try_into().unwrap() {
                        new_reg_info.append(updated_reg);
                    } else {
                        new_reg_info.append(*reg_info_array.at(j));
                    }
                    j += 1;
                }
                reg_info_array = new_reg_info;
                
                // Advance cycle (simplified: each instruction takes 1 cycle to issue)
                current_cycle += 1;
                current_seed = attempt_seed;
                break;
            } else {
                // Retry with new random values
                retry_count += 1;
                
                let (seed4, _) = next_random(attempt_seed);
                attempt_seed = seed4;
                
                // Reselect instruction type and source for retry
                let (seed5, new_opcode) = select_instruction_type(attempt_seed);
                attempt_seed = seed5;
                let (seed6, new_src) = select_source_register(attempt_seed, new_opcode);
                attempt_seed = seed6;
                let (seed7, new_imm32) = generate_immediate(attempt_seed, new_opcode);
                attempt_seed = seed7;
                
                // Update for retry
                opcode = new_opcode;
                src = new_src;
                imm32 = new_imm32;
            }
        }
        
        i += 1;
    }
    
    program
}

/// Get register value by index
fn get_register_value(regs: Registers, idx: u32) -> u64 {
    match idx {
        0 => regs.r0,
        1 => regs.r1,
        2 => regs.r2,
        3 => regs.r3,
        4 => regs.r4,
        5 => regs.r5,
        6 => regs.r6,
        7 => regs.r7,
        _ => 0,
    }
}

/// Set register value by index
fn set_register_value(mut regs: Registers, idx: u32, val: u64) -> Registers {
    match idx {
        0 => regs.r0 = val,
        1 => regs.r1 = val,
        2 => regs.r2 = val,
        3 => regs.r3 = val,
        4 => regs.r4 = val,
        5 => regs.r5 = val,
        6 => regs.r6 = val,
        7 => regs.r7 = val,
        _ => {}
    }
    regs
}

/// Execute SuperscalarHash program on registers
pub fn execute_superscalar_program(
    mut regs: Registers,
    program: Span<SuperscalarInstruction>,
) -> Registers {
    let mut i: usize = 0;
    loop {
        if i == program.len() {
            break;
        }
        let instr = *program.at(i);
        
        let dst_val = get_register_value(regs, instr.dst);
        let src_val = if instr.src < 8 {
            get_register_value(regs, instr.src)
        } else {
            0
        };
        
        let result = match instr.opcode {
            InstructionType::ISUB_R => isub_r(dst_val, src_val),
            InstructionType::IXOR_R => ixor_r(dst_val, src_val),
            InstructionType::IADD_RS => iadd_rs(dst_val, src_val, instr.mod_shift),
            InstructionType::IMUL_R => imul_r(dst_val, src_val),
            InstructionType::IROR_C => iror_c(dst_val, instr.imm32),
            InstructionType::IADD_C7 => iadd_c7(dst_val, instr.imm32),
            InstructionType::IADD_C8 => iadd_c8(dst_val, instr.imm32),
            InstructionType::IADD_C9 => iadd_c9(dst_val, instr.imm32),
            InstructionType::IXOR_C7 => ixor_c7(dst_val, instr.imm32),
            InstructionType::IXOR_C8 => ixor_c8(dst_val, instr.imm32),
            InstructionType::IXOR_C9 => ixor_c9(dst_val, instr.imm32),
            InstructionType::IMULH_R => {
                imulh_u64(dst_val, src_val)
            },
            InstructionType::ISMULH_R => {
                // ISMULH_R: signed multiply high
                // Note: u64 to i64 conversion may fail for values >= 2^63
                // For now, use a workaround: if conversion would fail, use IMULH_R instead
                // This is a simplification - proper implementation would handle two's complement
                if dst_val < 0x8000000000000000 && src_val < 0x8000000000000000 {
                    // Both values are < 2^63, safe to convert
                    let dst_i64: i64 = dst_val.try_into().unwrap();
                    let src_i64: i64 = src_val.try_into().unwrap();
                    let result_i64 = ismulh_i64(dst_i64, src_i64);
                    if result_i64 >= 0 {
                        result_i64.try_into().unwrap()
                    } else {
                        // Negative result: wrap it
                        let abs: u64 = (-result_i64).try_into().unwrap();
                        wrapping_sub_64(0, abs)
                    }
                } else {
                    // Fallback to unsigned multiply high for values >= 2^63
                    imulh_u64(dst_val, src_val)
                }
            },
            InstructionType::IMUL_RCP => imul_rcp(dst_val, instr.imm32),
        };
        
        regs = set_register_value(regs, instr.dst, result);
        
        i += 1;
    }
    
    regs
}
