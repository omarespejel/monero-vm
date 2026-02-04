// ============================================================
// AesHash1R Implementation for RandomX
// ============================================================
//
// Per RandomX specification (section 3.4):
// - Input: 2 MB scratchpad (processed in 64-byte blocks)
// - Output: 64 bytes (512 bits)
// - Process: Single AES round per 64-byte block
//
// This is the fingerprinting function that compresses the
// final scratchpad state into a 64-byte value for Blake2b-256.

use core::array::ArrayTrait;

// ============================================================
// AES S-Box (SubBytes transformation)
// ============================================================

// AES Forward S-Box (256 bytes)
fn aes_sbox(input: u8) -> u8 {
    let sbox: Array<u8> = array![
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ];
    *sbox.at(input.into())
}

// AES Inverse S-Box (for decryption)
fn aes_inv_sbox(input: u8) -> u8 {
    let inv_sbox: Array<u8> = array![
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    ];
    *inv_sbox.at(input.into())
}

// ============================================================
// GF(2^8) Multiplication (for MixColumns)
// ============================================================

/// Multiply by x in GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1
fn xtime(a: u8) -> u8 {
    let a_u16: u16 = a.into();
    let result: u16 = a_u16 * 2;
    if result >= 256 {
        (result ^ 0x11b).try_into().unwrap()
    } else {
        result.try_into().unwrap()
    }
}

/// Multiply two values in GF(2^8)
fn gf_mult(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut temp_a = a;
    let mut temp_b = b;
    
    loop {
        if temp_b == 0 {
            break;
        }
        if (temp_b & 1) != 0 {
            result = result ^ temp_a;
        }
        temp_a = xtime(temp_a);
        temp_b = temp_b / 2;
    }
    result
}

// ============================================================
// AES State (16 bytes = 4x4 matrix)
// ============================================================

#[derive(Copy, Drop)]
pub struct AesState {
    // Column-major order: state[col][row]
    pub s00: u8, pub s10: u8, pub s20: u8, pub s30: u8,  // Column 0
    pub s01: u8, pub s11: u8, pub s21: u8, pub s31: u8,  // Column 1
    pub s02: u8, pub s12: u8, pub s22: u8, pub s32: u8,  // Column 2
    pub s03: u8, pub s13: u8, pub s23: u8, pub s33: u8,  // Column 3
}

impl AesStateDefault of Default<AesState> {
    fn default() -> AesState {
        AesState {
            s00: 0, s10: 0, s20: 0, s30: 0,
            s01: 0, s11: 0, s21: 0, s31: 0,
            s02: 0, s12: 0, s22: 0, s32: 0,
            s03: 0, s13: 0, s23: 0, s33: 0,
        }
    }
}

/// Create AesState from 16 bytes (little-endian, column-major)
pub fn aes_state_from_bytes(bytes: Span<u8>) -> AesState {
    assert(bytes.len() >= 16, 'need 16 bytes');
    AesState {
        s00: *bytes.at(0), s10: *bytes.at(1), s20: *bytes.at(2), s30: *bytes.at(3),
        s01: *bytes.at(4), s11: *bytes.at(5), s21: *bytes.at(6), s31: *bytes.at(7),
        s02: *bytes.at(8), s12: *bytes.at(9), s22: *bytes.at(10), s32: *bytes.at(11),
        s03: *bytes.at(12), s13: *bytes.at(13), s23: *bytes.at(14), s33: *bytes.at(15),
    }
}

/// Convert AesState to 16 bytes
pub fn aes_state_to_bytes(state: AesState) -> Array<u8> {
    array![
        state.s00, state.s10, state.s20, state.s30,
        state.s01, state.s11, state.s21, state.s31,
        state.s02, state.s12, state.s22, state.s32,
        state.s03, state.s13, state.s23, state.s33,
    ]
}

// ============================================================
// AES Transformations
// ============================================================

/// SubBytes: Apply S-box to each byte
fn sub_bytes(state: AesState) -> AesState {
    AesState {
        s00: aes_sbox(state.s00), s10: aes_sbox(state.s10), s20: aes_sbox(state.s20), s30: aes_sbox(state.s30),
        s01: aes_sbox(state.s01), s11: aes_sbox(state.s11), s21: aes_sbox(state.s21), s31: aes_sbox(state.s31),
        s02: aes_sbox(state.s02), s12: aes_sbox(state.s12), s22: aes_sbox(state.s22), s32: aes_sbox(state.s32),
        s03: aes_sbox(state.s03), s13: aes_sbox(state.s13), s23: aes_sbox(state.s23), s33: aes_sbox(state.s33),
    }
}

/// Inverse SubBytes
fn inv_sub_bytes(state: AesState) -> AesState {
    AesState {
        s00: aes_inv_sbox(state.s00), s10: aes_inv_sbox(state.s10), s20: aes_inv_sbox(state.s20), s30: aes_inv_sbox(state.s30),
        s01: aes_inv_sbox(state.s01), s11: aes_inv_sbox(state.s11), s21: aes_inv_sbox(state.s21), s31: aes_inv_sbox(state.s31),
        s02: aes_inv_sbox(state.s02), s12: aes_inv_sbox(state.s12), s22: aes_inv_sbox(state.s22), s32: aes_inv_sbox(state.s32),
        s03: aes_inv_sbox(state.s03), s13: aes_inv_sbox(state.s13), s23: aes_inv_sbox(state.s23), s33: aes_inv_sbox(state.s33),
    }
}

/// ShiftRows: Shift rows left by 0, 1, 2, 3 positions
fn shift_rows(state: AesState) -> AesState {
    AesState {
        // Row 0: no shift
        s00: state.s00, s01: state.s01, s02: state.s02, s03: state.s03,
        // Row 1: shift left by 1
        s10: state.s11, s11: state.s12, s12: state.s13, s13: state.s10,
        // Row 2: shift left by 2
        s20: state.s22, s21: state.s23, s22: state.s20, s23: state.s21,
        // Row 3: shift left by 3
        s30: state.s33, s31: state.s30, s32: state.s31, s33: state.s32,
    }
}

/// Inverse ShiftRows: Shift rows right
fn inv_shift_rows(state: AesState) -> AesState {
    AesState {
        // Row 0: no shift
        s00: state.s00, s01: state.s01, s02: state.s02, s03: state.s03,
        // Row 1: shift right by 1
        s10: state.s13, s11: state.s10, s12: state.s11, s13: state.s12,
        // Row 2: shift right by 2
        s20: state.s22, s21: state.s23, s22: state.s20, s23: state.s21,
        // Row 3: shift right by 3
        s30: state.s31, s31: state.s32, s32: state.s33, s33: state.s30,
    }
}

/// MixColumns: Mix each column
fn mix_columns(state: AesState) -> AesState {
    // For each column: multiply by MDS matrix
    // [2 3 1 1]   [s0]
    // [1 2 3 1] × [s1]
    // [1 1 2 3]   [s2]
    // [3 1 1 2]   [s3]
    
    // Column 0
    let t0 = gf_mult(2, state.s00) ^ gf_mult(3, state.s10) ^ state.s20 ^ state.s30;
    let t1 = state.s00 ^ gf_mult(2, state.s10) ^ gf_mult(3, state.s20) ^ state.s30;
    let t2 = state.s00 ^ state.s10 ^ gf_mult(2, state.s20) ^ gf_mult(3, state.s30);
    let t3 = gf_mult(3, state.s00) ^ state.s10 ^ state.s20 ^ gf_mult(2, state.s30);
    
    // Column 1
    let t4 = gf_mult(2, state.s01) ^ gf_mult(3, state.s11) ^ state.s21 ^ state.s31;
    let t5 = state.s01 ^ gf_mult(2, state.s11) ^ gf_mult(3, state.s21) ^ state.s31;
    let t6 = state.s01 ^ state.s11 ^ gf_mult(2, state.s21) ^ gf_mult(3, state.s31);
    let t7 = gf_mult(3, state.s01) ^ state.s11 ^ state.s21 ^ gf_mult(2, state.s31);
    
    // Column 2
    let t8 = gf_mult(2, state.s02) ^ gf_mult(3, state.s12) ^ state.s22 ^ state.s32;
    let t9 = state.s02 ^ gf_mult(2, state.s12) ^ gf_mult(3, state.s22) ^ state.s32;
    let t10 = state.s02 ^ state.s12 ^ gf_mult(2, state.s22) ^ gf_mult(3, state.s32);
    let t11 = gf_mult(3, state.s02) ^ state.s12 ^ state.s22 ^ gf_mult(2, state.s32);
    
    // Column 3
    let t12 = gf_mult(2, state.s03) ^ gf_mult(3, state.s13) ^ state.s23 ^ state.s33;
    let t13 = state.s03 ^ gf_mult(2, state.s13) ^ gf_mult(3, state.s23) ^ state.s33;
    let t14 = state.s03 ^ state.s13 ^ gf_mult(2, state.s23) ^ gf_mult(3, state.s33);
    let t15 = gf_mult(3, state.s03) ^ state.s13 ^ state.s23 ^ gf_mult(2, state.s33);
    
    AesState {
        s00: t0, s10: t1, s20: t2, s30: t3,
        s01: t4, s11: t5, s21: t6, s31: t7,
        s02: t8, s12: t9, s22: t10, s32: t11,
        s03: t12, s13: t13, s23: t14, s33: t15,
    }
}

/// Inverse MixColumns
fn inv_mix_columns(state: AesState) -> AesState {
    // Inverse MDS matrix:
    // [14 11 13  9]
    // [ 9 14 11 13]
    // [13  9 14 11]
    // [11 13  9 14]
    
    // Column 0
    let t0 = gf_mult(14, state.s00) ^ gf_mult(11, state.s10) ^ gf_mult(13, state.s20) ^ gf_mult(9, state.s30);
    let t1 = gf_mult(9, state.s00) ^ gf_mult(14, state.s10) ^ gf_mult(11, state.s20) ^ gf_mult(13, state.s30);
    let t2 = gf_mult(13, state.s00) ^ gf_mult(9, state.s10) ^ gf_mult(14, state.s20) ^ gf_mult(11, state.s30);
    let t3 = gf_mult(11, state.s00) ^ gf_mult(13, state.s10) ^ gf_mult(9, state.s20) ^ gf_mult(14, state.s30);
    
    // Column 1
    let t4 = gf_mult(14, state.s01) ^ gf_mult(11, state.s11) ^ gf_mult(13, state.s21) ^ gf_mult(9, state.s31);
    let t5 = gf_mult(9, state.s01) ^ gf_mult(14, state.s11) ^ gf_mult(11, state.s21) ^ gf_mult(13, state.s31);
    let t6 = gf_mult(13, state.s01) ^ gf_mult(9, state.s11) ^ gf_mult(14, state.s21) ^ gf_mult(11, state.s31);
    let t7 = gf_mult(11, state.s01) ^ gf_mult(13, state.s11) ^ gf_mult(9, state.s21) ^ gf_mult(14, state.s31);
    
    // Column 2
    let t8 = gf_mult(14, state.s02) ^ gf_mult(11, state.s12) ^ gf_mult(13, state.s22) ^ gf_mult(9, state.s32);
    let t9 = gf_mult(9, state.s02) ^ gf_mult(14, state.s12) ^ gf_mult(11, state.s22) ^ gf_mult(13, state.s32);
    let t10 = gf_mult(13, state.s02) ^ gf_mult(9, state.s12) ^ gf_mult(14, state.s22) ^ gf_mult(11, state.s32);
    let t11 = gf_mult(11, state.s02) ^ gf_mult(13, state.s12) ^ gf_mult(9, state.s22) ^ gf_mult(14, state.s32);
    
    // Column 3
    let t12 = gf_mult(14, state.s03) ^ gf_mult(11, state.s13) ^ gf_mult(13, state.s23) ^ gf_mult(9, state.s33);
    let t13 = gf_mult(9, state.s03) ^ gf_mult(14, state.s13) ^ gf_mult(11, state.s23) ^ gf_mult(13, state.s33);
    let t14 = gf_mult(13, state.s03) ^ gf_mult(9, state.s13) ^ gf_mult(14, state.s23) ^ gf_mult(11, state.s33);
    let t15 = gf_mult(11, state.s03) ^ gf_mult(13, state.s13) ^ gf_mult(9, state.s23) ^ gf_mult(14, state.s33);
    
    AesState {
        s00: t0, s10: t1, s20: t2, s30: t3,
        s01: t4, s11: t5, s21: t6, s31: t7,
        s02: t8, s12: t9, s22: t10, s32: t11,
        s03: t12, s13: t13, s23: t14, s33: t15,
    }
}

/// AddRoundKey: XOR state with round key
fn add_round_key(state: AesState, key: AesState) -> AesState {
    AesState {
        s00: state.s00 ^ key.s00, s10: state.s10 ^ key.s10, s20: state.s20 ^ key.s20, s30: state.s30 ^ key.s30,
        s01: state.s01 ^ key.s01, s11: state.s11 ^ key.s11, s21: state.s21 ^ key.s21, s31: state.s31 ^ key.s31,
        s02: state.s02 ^ key.s02, s12: state.s12 ^ key.s12, s22: state.s22 ^ key.s22, s32: state.s32 ^ key.s32,
        s03: state.s03 ^ key.s03, s13: state.s13 ^ key.s13, s23: state.s23 ^ key.s23, s33: state.s33 ^ key.s33,
    }
}

// ============================================================
// AES Single Round Operations
// ============================================================

/// Single AES encryption round: ShiftRows → SubBytes → MixColumns → AddRoundKey
pub fn aes_enc_round(state: AesState, key: AesState) -> AesState {
    let s1 = shift_rows(state);
    let s2 = sub_bytes(s1);
    let s3 = mix_columns(s2);
    add_round_key(s3, key)
}

/// Single AES decryption round: InvShiftRows → InvSubBytes → InvMixColumns → AddRoundKey
pub fn aes_dec_round(state: AesState, key: AesState) -> AesState {
    let s1 = inv_shift_rows(state);
    let s2 = inv_sub_bytes(s1);
    let s3 = inv_mix_columns(s2);
    add_round_key(s3, key)
}

// ============================================================
// AesHash1R Constants
// ============================================================

/// Initial state for AesHash1R (from RandomX spec)
/// state0, state1, state2, state3 = Hash512("RandomX AesHash1R state")
pub fn get_aes_hash_initial_state() -> (AesState, AesState, AesState, AesState) {
    // state0 = 0d 2c b5 92 de 56 a8 9f 47 db 82 cc ad 3a 98 d7
    let state0 = AesState {
        s00: 0x0d, s10: 0x2c, s20: 0xb5, s30: 0x92,
        s01: 0xde, s11: 0x56, s21: 0xa8, s31: 0x9f,
        s02: 0x47, s12: 0xdb, s22: 0x82, s32: 0xcc,
        s03: 0xad, s13: 0x3a, s23: 0x98, s33: 0xd7,
    };
    // state1 = 6e 99 8d 33 98 b7 c7 15 5a 12 9e f5 57 80 e7 ac
    let state1 = AesState {
        s00: 0x6e, s10: 0x99, s20: 0x8d, s30: 0x33,
        s01: 0x98, s11: 0xb7, s21: 0xc7, s31: 0x15,
        s02: 0x5a, s12: 0x12, s22: 0x9e, s32: 0xf5,
        s03: 0x57, s13: 0x80, s23: 0xe7, s33: 0xac,
    };
    // state2 = 17 00 77 6a d0 c7 62 ae 6b 50 79 50 e4 7c a0 e8
    let state2 = AesState {
        s00: 0x17, s10: 0x00, s20: 0x77, s30: 0x6a,
        s01: 0xd0, s11: 0xc7, s21: 0x62, s31: 0xae,
        s02: 0x6b, s12: 0x50, s22: 0x79, s32: 0x50,
        s03: 0xe4, s13: 0x7c, s23: 0xa0, s33: 0xe8,
    };
    // state3 = 0c 24 0a 63 8d 82 ad 07 05 00 a1 79 48 49 99 7e
    let state3 = AesState {
        s00: 0x0c, s10: 0x24, s20: 0x0a, s30: 0x63,
        s01: 0x8d, s11: 0x82, s21: 0xad, s31: 0x07,
        s02: 0x05, s12: 0x00, s22: 0xa1, s32: 0x79,
        s03: 0x48, s13: 0x49, s23: 0x99, s33: 0x7e,
    };
    (state0, state1, state2, state3)
}

/// Extra keys for finalization
/// xkey0, xkey1 = Hash256("RandomX AesHash1R xkeys")
pub fn get_aes_hash_extra_keys() -> (AesState, AesState) {
    // xkey0 = 89 83 fa f6 9f 94 24 8b bf 56 dc 90 01 02 89 06
    let xkey0 = AesState {
        s00: 0x89, s10: 0x83, s20: 0xfa, s30: 0xf6,
        s01: 0x9f, s11: 0x94, s21: 0x24, s31: 0x8b,
        s02: 0xbf, s12: 0x56, s22: 0xdc, s32: 0x90,
        s03: 0x01, s13: 0x02, s23: 0x89, s33: 0x06,
    };
    // xkey1 = d1 63 b2 61 3c e0 f4 51 c6 43 10 ee 9b f9 18 ed
    let xkey1 = AesState {
        s00: 0xd1, s10: 0x63, s20: 0xb2, s30: 0x61,
        s01: 0x3c, s11: 0xe0, s21: 0xf4, s31: 0x51,
        s02: 0xc6, s12: 0x43, s22: 0x10, s32: 0xee,
        s03: 0x9b, s13: 0xf9, s23: 0x18, s33: 0xed,
    };
    (xkey0, xkey1)
}

// ============================================================
// AesHash1R Main Function
// ============================================================

/// 64-byte hash state
#[derive(Drop)]
pub struct AesHash1RState {
    pub col0: AesState,
    pub col1: AesState,
    pub col2: AesState,
    pub col3: AesState,
}

/// Process a single 64-byte block
/// Per spec: columns 0,2 encrypt, columns 1,3 decrypt
pub fn aes_hash_process_block(
    state: AesHash1RState,
    block: Span<u8>
) -> AesHash1RState {
    assert(block.len() >= 64, 'need 64 bytes');
    
    // Extract 4 keys from the 64-byte block
    let key0 = aes_state_from_bytes(block.slice(0, 16));
    let key1 = aes_state_from_bytes(block.slice(16, 16));
    let key2 = aes_state_from_bytes(block.slice(32, 16));
    let key3 = aes_state_from_bytes(block.slice(48, 16));
    
    // Apply AES rounds
    // Column 0: encrypt, Column 1: decrypt, Column 2: encrypt, Column 3: decrypt
    let new_col0 = aes_enc_round(state.col0, key0);
    let new_col1 = aes_dec_round(state.col1, key1);
    let new_col2 = aes_enc_round(state.col2, key2);
    let new_col3 = aes_dec_round(state.col3, key3);
    
    AesHash1RState {
        col0: new_col0,
        col1: new_col1,
        col2: new_col2,
        col3: new_col3,
    }
}

/// Apply final rounds with extra keys
pub fn aes_hash_finalize(state: AesHash1RState) -> AesHash1RState {
    let (xkey0, xkey1) = get_aes_hash_extra_keys();
    
    // First extra round
    let s1_col0 = aes_enc_round(state.col0, xkey0);
    let s1_col1 = aes_dec_round(state.col1, xkey0);
    let s1_col2 = aes_enc_round(state.col2, xkey0);
    let s1_col3 = aes_dec_round(state.col3, xkey0);
    
    // Second extra round
    let s2_col0 = aes_enc_round(s1_col0, xkey1);
    let s2_col1 = aes_dec_round(s1_col1, xkey1);
    let s2_col2 = aes_enc_round(s1_col2, xkey1);
    let s2_col3 = aes_dec_round(s1_col3, xkey1);
    
    AesHash1RState {
        col0: s2_col0,
        col1: s2_col1,
        col2: s2_col2,
        col3: s2_col3,
    }
}

/// Convert final state to 64 bytes
pub fn aes_hash_state_to_bytes(state: AesHash1RState) -> Array<u8> {
    let mut result: Array<u8> = ArrayTrait::new();
    
    let bytes0 = aes_state_to_bytes(state.col0);
    let bytes1 = aes_state_to_bytes(state.col1);
    let bytes2 = aes_state_to_bytes(state.col2);
    let bytes3 = aes_state_to_bytes(state.col3);
    
    // Append all 64 bytes
    let mut i: usize = 0;
    loop {
        if i >= 16 { break; }
        result.append(*bytes0.at(i));
        i += 1;
    }
    let mut i: usize = 0;
    loop {
        if i >= 16 { break; }
        result.append(*bytes1.at(i));
        i += 1;
    }
    let mut i: usize = 0;
    loop {
        if i >= 16 { break; }
        result.append(*bytes2.at(i));
        i += 1;
    }
    let mut i: usize = 0;
    loop {
        if i >= 16 { break; }
        result.append(*bytes3.at(i));
        i += 1;
    }
    
    result
}

/// Main AesHash1R function
/// Input: scratchpad (2 MB, processed in 64-byte blocks)
/// Output: 64 bytes
pub fn aes_hash_1r(scratchpad: Span<u8>) -> Array<u8> {
    // Initialize state
    let (s0, s1, s2, s3) = get_aes_hash_initial_state();
    let mut state = AesHash1RState {
        col0: s0, col1: s1, col2: s2, col3: s3,
    };
    
    // Process input in 64-byte blocks
    let num_blocks = scratchpad.len() / 64;
    let mut block_idx: usize = 0;
    
    loop {
        if block_idx >= num_blocks {
            break;
        }
        
        let block_start = block_idx * 64;
        let block = scratchpad.slice(block_start, 64);
        state = aes_hash_process_block(state, block);
        
        block_idx += 1;
    }
    
    // Apply finalization rounds
    let final_state = aes_hash_finalize(state);
    
    // Convert to bytes
    aes_hash_state_to_bytes(final_state)
}
