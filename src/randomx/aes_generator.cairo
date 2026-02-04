// ============================================================
// AesGenerator1R Implementation for RandomX
// ============================================================
//
// Per RandomX specification (section 3.2):
// - Pseudo-random number generator using single AES rounds
// - Produces 64 bytes per iteration
// - Used for scratchpad initialization
//
// This is DIFFERENT from AesHash1R:
// - AesGenerator1R: PRNG that generates bytes
// - AesHash1R: Hash function that compresses bytes

use core::array::ArrayTrait;
use super::aes_hash::{AesState, aes_state_from_bytes, aes_state_to_bytes, aes_enc_round, aes_dec_round};

// ============================================================
// AesGenerator1R Constants
// ============================================================

/// Round keys for AesGenerator1R
/// Generated from Hash512("RandomX AesGenerator1R keys")
pub fn get_aes_gen1r_keys() -> (AesState, AesState, AesState, AesState) {
    // key0 = 53 a5 ac 6d 09 66 71 62 2b 55 b5 db 17 49 f4 b4
    let key0 = AesState {
        s00: 0x53, s10: 0xa5, s20: 0xac, s30: 0x6d,
        s01: 0x09, s11: 0x66, s21: 0x71, s31: 0x62,
        s02: 0x2b, s12: 0x55, s22: 0xb5, s32: 0xdb,
        s03: 0x17, s13: 0x49, s23: 0xf4, s33: 0xb4,
    };
    // key1 = 07 af 7c 6d 0d 71 6a 84 78 d3 25 17 4e dc a1 0d
    let key1 = AesState {
        s00: 0x07, s10: 0xaf, s20: 0x7c, s30: 0x6d,
        s01: 0x0d, s11: 0x71, s21: 0x6a, s31: 0x84,
        s02: 0x78, s12: 0xd3, s22: 0x25, s32: 0x17,
        s03: 0x4e, s13: 0xdc, s23: 0xa1, s33: 0x0d,
    };
    // key2 = f1 62 12 3f c6 7e 94 9f 4f 79 c0 f4 45 e3 20 3e
    let key2 = AesState {
        s00: 0xf1, s10: 0x62, s20: 0x12, s30: 0x3f,
        s01: 0xc6, s11: 0x7e, s21: 0x94, s31: 0x9f,
        s02: 0x4f, s12: 0x79, s22: 0xc0, s32: 0xf4,
        s03: 0x45, s13: 0xe3, s23: 0x20, s33: 0x3e,
    };
    // key3 = 35 81 ef 6a 7c 31 ba b1 88 4c 31 16 54 91 16 49
    let key3 = AesState {
        s00: 0x35, s10: 0x81, s20: 0xef, s30: 0x6a,
        s01: 0x7c, s11: 0x31, s21: 0xba, s31: 0xb1,
        s02: 0x88, s12: 0x4c, s22: 0x31, s32: 0x16,
        s03: 0x54, s13: 0x91, s23: 0x16, s33: 0x49,
    };
    (key0, key1, key2, key3)
}

// ============================================================
// AesGenerator1R State
// ============================================================

/// 64-byte generator state (4 columns)
#[derive(Drop)]
pub struct AesGenerator1RState {
    pub col0: AesState,
    pub col1: AesState,
    pub col2: AesState,
    pub col3: AesState,
}

/// Initialize generator from 64-byte seed
pub fn aes_generator1r_init(seed: Span<u8>) -> AesGenerator1RState {
    assert(seed.len() >= 64, 'need 64 byte seed');
    
    AesGenerator1RState {
        col0: aes_state_from_bytes(seed.slice(0, 16)),
        col1: aes_state_from_bytes(seed.slice(16, 16)),
        col2: aes_state_from_bytes(seed.slice(32, 16)),
        col3: aes_state_from_bytes(seed.slice(48, 16)),
    }
}

/// Generate one iteration (64 bytes)
/// Per spec:
/// - Column 0: AES decrypt with key0
/// - Column 1: AES encrypt with key1
/// - Column 2: AES decrypt with key2
/// - Column 3: AES encrypt with key3
pub fn aes_generator1r_next(state: AesGenerator1RState) -> (AesGenerator1RState, Array<u8>) {
    let (key0, key1, key2, key3) = get_aes_gen1r_keys();
    
    // Apply AES rounds
    let new_col0 = aes_dec_round(state.col0, key0);
    let new_col1 = aes_enc_round(state.col1, key1);
    let new_col2 = aes_dec_round(state.col2, key2);
    let new_col3 = aes_enc_round(state.col3, key3);
    
    let new_state = AesGenerator1RState {
        col0: new_col0,
        col1: new_col1,
        col2: new_col2,
        col3: new_col3,
    };
    
    // Convert to bytes
    let mut output: Array<u8> = ArrayTrait::new();
    
    let bytes0 = aes_state_to_bytes(new_col0);
    let bytes1 = aes_state_to_bytes(new_col1);
    let bytes2 = aes_state_to_bytes(new_col2);
    let bytes3 = aes_state_to_bytes(new_col3);
    
    let mut i: usize = 0;
    loop {
        if i >= 16 { break; }
        output.append(*bytes0.at(i));
        i += 1;
    }
    let mut i: usize = 0;
    loop {
        if i >= 16 { break; }
        output.append(*bytes1.at(i));
        i += 1;
    }
    let mut i: usize = 0;
    loop {
        if i >= 16 { break; }
        output.append(*bytes2.at(i));
        i += 1;
    }
    let mut i: usize = 0;
    loop {
        if i >= 16 { break; }
        output.append(*bytes3.at(i));
        i += 1;
    }
    
    (new_state, output)
}

/// Generate N bytes
pub fn aes_generator1r_fill(seed: Span<u8>, num_bytes: usize) -> Array<u8> {
    let mut state = aes_generator1r_init(seed);
    let mut output: Array<u8> = ArrayTrait::new();
    
    let num_iterations = (num_bytes + 63) / 64;
    let mut iter: usize = 0;
    
    loop {
        if iter >= num_iterations {
            break;
        }
        
        let (new_state, chunk) = aes_generator1r_next(state);
        state = new_state;
        
        // Append chunk (up to remaining bytes needed)
        let mut i: usize = 0;
        loop {
            if i >= 64 || output.len() >= num_bytes {
                break;
            }
            output.append(*chunk.at(i));
            i += 1;
        }
        
        iter += 1;
    }
    
    output
}
