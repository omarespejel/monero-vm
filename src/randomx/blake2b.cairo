// ============================================================
// Blake2b Implementation for RandomX SuperscalarHash
// ============================================================
// 
// IMPLEMENTATION DECISION: Adapted from Herodotus/integrity Blake2s
// 
// Source of truth: RFC 7693 (https://datatracker.ietf.org/doc/html/rfc7693)
// RandomX reference: https://github.com/tevador/RandomX/blob/master/src/blake2/blake2b.c
// Architecture based on: Herodotus/integrity blake2s.cairo (zksecurity audited)
//   - See: https://github.com/HerodotusDev/integrity/blob/main/src/common/blake2s.cairo
//   - Audit: zksecurity.pdf in /audit folder of integrity repo
//
// Key differences from Blake2s:
// - Word size: 64-bit (vs 32-bit)
// - Rounds: 12 (vs 10)  
// - Rotations: R1=32, R2=24, R3=16, R4=63 (vs 16, 12, 8, 7)
// - IV constants: Different values for 64-bit words
//
// VERIFIED AGAINST:
// - RFC 7693 Section 2.6 (IV constants)
// - RFC 7693 Section 2.7 (SIGMA permutation - identical for both variants)
// - RandomX blake2b.c constants

use core::array::ArrayTrait;
use core::traits::TryInto;

// ============================================================
// Blake2b IV Constants (RFC 7693 Section 2.6)
// CRITICAL: These MUST match exactly for deterministic output
// ============================================================

pub const BLAKE2B_IV_0: u64 = 0x6a09e667f3bcc908;
pub const BLAKE2B_IV_1: u64 = 0xbb67ae8584caa73b;
pub const BLAKE2B_IV_2: u64 = 0x3c6ef372fe94f82b;
pub const BLAKE2B_IV_3: u64 = 0xa54ff53a5f1d36f1;
pub const BLAKE2B_IV_4: u64 = 0x510e527fade682d1;
pub const BLAKE2B_IV_5: u64 = 0x9b05688c2b3e6c1f;
pub const BLAKE2B_IV_6: u64 = 0x1f83d9abfb41bd6b;
pub const BLAKE2B_IV_7: u64 = 0x5be0cd19137e2179;

/// Get Blake2b IV as array
pub fn get_blake2b_iv() -> Array<u64> {
    array![
        BLAKE2B_IV_0, BLAKE2B_IV_1, BLAKE2B_IV_2, BLAKE2B_IV_3,
        BLAKE2B_IV_4, BLAKE2B_IV_5, BLAKE2B_IV_6, BLAKE2B_IV_7
    ]
}

// ============================================================
// SIGMA Permutation Table (RFC 7693 Section 2.7)
// Identical for Blake2b and Blake2s
// For rounds 10, 11: use SIGMA[0], SIGMA[1] respectively
// ============================================================

/// Get SIGMA permutation for a given round (0-11)
/// Rounds 10, 11 wrap to SIGMA[0], SIGMA[1]
pub fn get_sigma(round: usize) -> Array<u8> {
    let idx = round % 10;
    match idx {
        0 => array![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        1 => array![14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        2 => array![11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        3 => array![7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        4 => array![9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        5 => array![2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        6 => array![12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        7 => array![13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        8 => array![6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        9 => array![10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        _ => array![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], // fallback
    }
}

// ============================================================
// Blake2b Rotation Constants
// DIFFERENT from Blake2s: (32, 24, 16, 63) vs (16, 12, 8, 7)
// ============================================================

const R1: u32 = 32;
const R2: u32 = 24;
const R3: u32 = 16;
const R4: u32 = 63;

// ============================================================
// Blake2b State Structure
// ============================================================

#[derive(Copy, Drop)]
pub struct Blake2bState {
    pub h0: u64, pub h1: u64, pub h2: u64, pub h3: u64,
    pub h4: u64, pub h5: u64, pub h6: u64, pub h7: u64,
    pub t0: u64,      // Counter low
    pub t1: u64,      // Counter high
    pub f0: u64,      // Finalization flag
}

// ============================================================
// Helper Functions
// ============================================================

const MASK_64: u128 = 0xffffffffffffffff;
const POW2_64: u128 = 0x10000000000000000;

fn to_u128(value: u64) -> u128 {
    value.into()
}

fn wrap_u64(value: u128) -> u64 {
    let masked = value & MASK_64;
    masked.try_into().unwrap()
}

fn wrapping_add_64(a: u64, b: u64) -> u64 {
    wrap_u64(to_u128(a) + to_u128(b))
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

/// Rotate right 64-bit
fn rotr64(value: u64, shift: u32) -> u64 {
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

// ============================================================
// Blake2b G Function (Quarter-Round Mixing)
// RFC 7693 Section 3.1
// ============================================================

/// G function: mixing operation for Blake2b
/// Operates on working vector v at indices a, b, c, d
/// with message words x and y
pub fn blake2b_g(
    v: Span<u64>,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: u64,
    y: u64,
) -> Array<u64> {
    let mut result = ArrayTrait::new();
    let mut i: usize = 0;
    loop {
        if i == v.len() {
            break;
        }
        result.append(*v.at(i));
        i += 1;
    }
    
    // Get current values
    let mut va = *v.at(a);
    let mut vb = *v.at(b);
    let mut vc = *v.at(c);
    let mut vd = *v.at(d);
    
    // Step 1: a = a + b + x
    va = wrapping_add_64(wrapping_add_64(va, vb), x);
    // Step 2: d = (d ^ a) >>> R1
    vd = rotr64(vd ^ va, R1);
    // Step 3: c = c + d
    vc = wrapping_add_64(vc, vd);
    // Step 4: b = (b ^ c) >>> R2
    vb = rotr64(vb ^ vc, R2);
    // Step 5: a = a + b + y
    va = wrapping_add_64(wrapping_add_64(va, vb), y);
    // Step 6: d = (d ^ a) >>> R3
    vd = rotr64(vd ^ va, R3);
    // Step 7: c = c + d
    vc = wrapping_add_64(vc, vd);
    // Step 8: b = (b ^ c) >>> R4
    vb = rotr64(vb ^ vc, R4);
    
    // Update result array
    let mut new_result = ArrayTrait::new();
    let mut j: usize = 0;
    loop {
        if j == result.len() {
            break;
        }
        if j == a {
            new_result.append(va);
        } else if j == b {
            new_result.append(vb);
        } else if j == c {
            new_result.append(vc);
        } else if j == d {
            new_result.append(vd);
        } else {
            new_result.append(*result.at(j));
        }
        j += 1;
    }
    
    new_result
}

// ============================================================
// Blake2b Initialization
// ============================================================

/// Initialize Blake2b state for given output length (in bytes)
pub fn blake2b_init(outlen: u8) -> Blake2bState {
    // Parameter block: [digest_length, key_length, fanout, depth, ...]
    // For simple hashing: 0x01010000 | outlen
    let param: u64 = 0x01010000 | outlen.into();
    
    Blake2bState {
        h0: BLAKE2B_IV_0 ^ param,
        h1: BLAKE2B_IV_1,
        h2: BLAKE2B_IV_2,
        h3: BLAKE2B_IV_3,
        h4: BLAKE2B_IV_4,
        h5: BLAKE2B_IV_5,
        h6: BLAKE2B_IV_6,
        h7: BLAKE2B_IV_7,
        t0: 0,
        t1: 0,
        f0: 0,
    }
}

// ============================================================
// Blake2b Compression Function
// ============================================================

/// Blake2b compression function
/// Processes a 128-byte (16 × u64) message block
pub fn blake2b_compress(
    state: Blake2bState,
    block: Span<u64>,
    bytes_compressed: u64,
    is_last: bool,
) -> Blake2bState {
    // Initialize working vector v[0..15]
    // v[0..7] = h[0..7]
    // v[8..15] = IV[0..7]
    let mut v = ArrayTrait::new();
    v.append(state.h0);
    v.append(state.h1);
    v.append(state.h2);
    v.append(state.h3);
    v.append(state.h4);
    v.append(state.h5);
    v.append(state.h6);
    v.append(state.h7);
    v.append(BLAKE2B_IV_0);
    v.append(BLAKE2B_IV_1);
    v.append(BLAKE2B_IV_2);
    v.append(BLAKE2B_IV_3);
    v.append(BLAKE2B_IV_4);
    v.append(BLAKE2B_IV_5);
    v.append(BLAKE2B_IV_6);
    v.append(BLAKE2B_IV_7);
    
    // XOR counter into v[12..13]
    let t0 = state.t0 + bytes_compressed;
    let v12 = *v.at(12) ^ t0;
    let v13 = *v.at(13) ^ state.t1;
    
    // XOR finalization flag into v[14] if last block
    let v14 = if is_last {
        *v.at(14) ^ 0xFFFFFFFFFFFFFFFF
    } else {
        *v.at(14)
    };
    
    // Update v with counter and flag
    let mut v_updated = ArrayTrait::new();
    let mut k: usize = 0;
    loop {
        if k == 16 {
            break;
        }
        if k == 12 {
            v_updated.append(v12);
        } else if k == 13 {
            v_updated.append(v13);
        } else if k == 14 {
            v_updated.append(v14);
        } else {
            v_updated.append(*v.at(k));
        }
        k += 1;
    }
    
    // 12 rounds of mixing (Blake2b uses 12 rounds, not 10!)
    let mut round: usize = 0;
    let mut v_current = v_updated;
    loop {
        if round == 12 {
            break;
        }
        
        // Get sigma for this round (rounds 10, 11 wrap to 0, 1)
        let s = get_sigma(round);
        
        // Column step
        v_current = blake2b_g(v_current.span(), 0, 4, 8, 12, *block.at((*s.at(0)).into()), *block.at((*s.at(1)).into()));
        v_current = blake2b_g(v_current.span(), 1, 5, 9, 13, *block.at((*s.at(2)).into()), *block.at((*s.at(3)).into()));
        v_current = blake2b_g(v_current.span(), 2, 6, 10, 14, *block.at((*s.at(4)).into()), *block.at((*s.at(5)).into()));
        v_current = blake2b_g(v_current.span(), 3, 7, 11, 15, *block.at((*s.at(6)).into()), *block.at((*s.at(7)).into()));
        
        // Diagonal step
        v_current = blake2b_g(v_current.span(), 0, 5, 10, 15, *block.at((*s.at(8)).into()), *block.at((*s.at(9)).into()));
        v_current = blake2b_g(v_current.span(), 1, 6, 11, 12, *block.at((*s.at(10)).into()), *block.at((*s.at(11)).into()));
        v_current = blake2b_g(v_current.span(), 2, 7, 8, 13, *block.at((*s.at(12)).into()), *block.at((*s.at(13)).into()));
        v_current = blake2b_g(v_current.span(), 3, 4, 9, 14, *block.at((*s.at(14)).into()), *block.at((*s.at(15)).into()));
        
        round += 1;
    }
    
    // Finalize: h[i] = h[i] ^ v[i] ^ v[i+8]
    Blake2bState {
        h0: state.h0 ^ *v_current.at(0) ^ *v_current.at(8),
        h1: state.h1 ^ *v_current.at(1) ^ *v_current.at(9),
        h2: state.h2 ^ *v_current.at(2) ^ *v_current.at(10),
        h3: state.h3 ^ *v_current.at(3) ^ *v_current.at(11),
        h4: state.h4 ^ *v_current.at(4) ^ *v_current.at(12),
        h5: state.h5 ^ *v_current.at(5) ^ *v_current.at(13),
        h6: state.h6 ^ *v_current.at(6) ^ *v_current.at(14),
        h7: state.h7 ^ *v_current.at(7) ^ *v_current.at(15),
        t0: t0,
        t1: state.t1,
        f0: if is_last { 1 } else { 0 },
    }
}

// ============================================================
// Blake2bGenerator (RandomX PRNG)
// Source: RandomX blake2_generator.cpp
// 
// This generator produces a continuous stream of random bytes
// by repeatedly hashing its internal 64-byte state.
// ============================================================

#[derive(Copy, Drop)]
pub struct Blake2bGenerator {
    pub d0: u64, pub d1: u64, pub d2: u64, pub d3: u64,
    pub d4: u64, pub d5: u64, pub d6: u64, pub d7: u64,
    pub data_index: u32,    // Current position in data (0-63)
}

/// Create new Blake2bGenerator from seed and nonce
/// seed: up to 60 bytes
/// nonce: stored at offset 60 (4 bytes, little-endian)
pub fn blake2b_generator_new(seed: Span<u8>, nonce: u32) -> Blake2bGenerator {
    // Initialize 64-byte data buffer
    let mut data_bytes: Array<u8> = ArrayTrait::new();
    
    // Copy seed (up to 60 bytes)
    let seed_len = if seed.len() > 60 { 60 } else { seed.len() };
    let mut i: usize = 0;
    loop {
        if i == seed_len {
            break;
        }
        data_bytes.append(*seed.at(i));
        i += 1;
    }
    
    // Pad with zeros to offset 60
    loop {
        if data_bytes.len() == 60 {
            break;
        }
        data_bytes.append(0);
    }
    
    // Store nonce at offset 60 (little-endian)
    data_bytes.append((nonce & 0xFF).try_into().unwrap());
    data_bytes.append(((nonce / 256) & 0xFF).try_into().unwrap());
    data_bytes.append(((nonce / 65536) & 0xFF).try_into().unwrap());
    data_bytes.append(((nonce / 16777216) & 0xFF).try_into().unwrap());
    
    // Convert bytes to u64 values (little-endian)
    let data = bytes_to_u64_array(data_bytes.span());
    
    Blake2bGenerator {
        d0: *data.at(0),
        d1: *data.at(1),
        d2: *data.at(2),
        d3: *data.at(3),
        d4: *data.at(4),
        d5: *data.at(5),
        d6: *data.at(6),
        d7: *data.at(7),
        data_index: 64, // Force immediate hash on first access
    }
}

/// Get single byte from generator
pub fn blake2b_generator_get_byte(gen: Blake2bGenerator) -> (Blake2bGenerator, u8) {
    let mut new_gen = check_and_hash(gen, 1);
    
    // Extract byte at current index
    let word_idx = new_gen.data_index / 8;
    let byte_idx = new_gen.data_index % 8;
    
    // Get word based on index
    let word = match word_idx {
        0 => new_gen.d0,
        1 => new_gen.d1,
        2 => new_gen.d2,
        3 => new_gen.d3,
        4 => new_gen.d4,
        5 => new_gen.d5,
        6 => new_gen.d6,
        7 => new_gen.d7,
        _ => 0,
    };
    
    // Extract byte (little-endian)
    let shift = byte_idx * 8;
    let byte: u8 = ((word / pow2_u128(shift).try_into().unwrap()) & 0xFF).try_into().unwrap();
    
    new_gen.data_index += 1;
    
    (new_gen, byte)
}

/// Get u32 from generator (little-endian)
pub fn blake2b_generator_get_u32(gen: Blake2bGenerator) -> (Blake2bGenerator, u32) {
    let mut new_gen = check_and_hash(gen, 4);
    
    // Get 4 bytes
    let (gen1, b0) = blake2b_generator_get_byte(new_gen);
    let (gen2, b1) = blake2b_generator_get_byte(gen1);
    let (gen3, b2) = blake2b_generator_get_byte(gen2);
    let (gen4, b3) = blake2b_generator_get_byte(gen3);
    
    // Combine little-endian
    let value: u32 = b0.into() 
        + b1.into() * 256 
        + b2.into() * 65536 
        + b3.into() * 16777216;
    
    (gen4, value)
}

/// Check if we need more data and hash if necessary
fn check_and_hash(gen: Blake2bGenerator, bytes_needed: u32) -> Blake2bGenerator {
    if gen.data_index + bytes_needed > 64 {
        // Hash current data to produce new data
        let state = blake2b_init(64);
        
        // Convert data to block (already in u64 format)
        let mut block: Array<u64> = ArrayTrait::new();
        block.append(gen.d0);
        block.append(gen.d1);
        block.append(gen.d2);
        block.append(gen.d3);
        block.append(gen.d4);
        block.append(gen.d5);
        block.append(gen.d6);
        block.append(gen.d7);
        // Pad block to 16 words
        block.append(0);
        block.append(0);
        block.append(0);
        block.append(0);
        block.append(0);
        block.append(0);
        block.append(0);
        block.append(0);
        
        let new_state = blake2b_compress(state, block.span(), 64, true);
        
        Blake2bGenerator {
            d0: new_state.h0,
            d1: new_state.h1,
            d2: new_state.h2,
            d3: new_state.h3,
            d4: new_state.h4,
            d5: new_state.h5,
            d6: new_state.h6,
            d7: new_state.h7,
            data_index: 0,
        }
    } else {
        gen
    }
}

/// Convert byte span to u64 array (little-endian)
fn bytes_to_u64_array(bytes: Span<u8>) -> Array<u64> {
    let mut result: Array<u64> = ArrayTrait::new();
    let mut word_idx: usize = 0;
    
    loop {
        if word_idx == 8 {
            break;
        }
        let base = word_idx * 8;
        let mut word: u64 = 0;
        let mut byte_idx: usize = 0;
        loop {
            if byte_idx == 8 {
                break;
            }
            let idx = base + byte_idx;
            if idx < bytes.len() {
                let b: u64 = (*bytes.at(idx)).into();
                let shift: u64 = pow2_u128(byte_idx.try_into().unwrap() * 8).try_into().unwrap();
                word = word + b * shift;
            }
            byte_idx += 1;
        }
        result.append(word);
        word_idx += 1;
    }
    
    result
}
