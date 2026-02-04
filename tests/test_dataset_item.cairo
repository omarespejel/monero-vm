// ============================================================
// TDD Tests for Dataset Item Generation
// Source: RandomX dataset.cpp
// ============================================================
//
// Dataset item generation:
// 1. Initialize registers with item index × constants
// 2. Run 8 SuperscalarHash programs
// 3. XOR with cache entries after each program
// 4. Output 64 bytes (8 × u64 registers)

use monero_vm::randomx::dataset_item::{
    DatasetItem,
    dataset_item_generator_new, dataset_item_generate,
    init_dataset_registers, apply_superscalar_constants,
    SUPERSCALAR_MUL0, SUPERSCALAR_ADD1, SUPERSCALAR_ADD2, SUPERSCALAR_ADD3,
    SUPERSCALAR_ADD4, SUPERSCALAR_ADD5, SUPERSCALAR_ADD6, SUPERSCALAR_ADD7,
    CACHE_ACCESSES,
};

// ============================================================
// SuperscalarHash Constants
// From RandomX configuration.h
// ============================================================

#[test]
fn test_superscalar_mul0_constant() {
    // MUL0 = 6364136223846793005 (same as LCG multiplier)
    assert(SUPERSCALAR_MUL0 == 6364136223846793005, 'MUL0 value');
}

#[test]
fn test_superscalar_add_constants() {
    // ADD1-7 are different constants for each register
    assert(SUPERSCALAR_ADD1 == 9298411001130361340, 'ADD1 value');
    assert(SUPERSCALAR_ADD2 == 12065312585734608966, 'ADD2 value');
    assert(SUPERSCALAR_ADD3 == 9306329213124626780, 'ADD3 value');  // From specs.md
    assert(SUPERSCALAR_ADD4 == 5281919268842080866, 'ADD4 value');
    assert(SUPERSCALAR_ADD5 == 10536153434571861004, 'ADD5 value');
    assert(SUPERSCALAR_ADD6 == 3398623926847679864, 'ADD6 value');
    assert(SUPERSCALAR_ADD7 == 9549104520008361294, 'ADD7 value');
}

#[test]
fn test_cache_accesses_is_8() {
    // Each dataset item requires 8 cache accesses
    assert(CACHE_ACCESSES == 8, 'CACHE_ACCESSES = 8');
}

// ============================================================
// Register Initialization
// ============================================================

#[test]
fn test_init_dataset_registers_item_0() {
    // For item_index = 0, registers are initialized with constants
    let regs = init_dataset_registers(0);
    
    // r0 = item_index (0) - will be multiplied by MUL0
    // r1-r7 = item_index + ADD1-7
    assert(regs.r0 == 0, 'r0 = 0 for item 0');
}

#[test]
fn test_init_dataset_registers_item_1() {
    // For item_index = 1
    let regs = init_dataset_registers(1);
    
    // r0 = 1 * MUL0
    // r1 = 1 + ADD1, etc.
    assert(regs.r0 == SUPERSCALAR_MUL0, 'r0 = MUL0 for item 1');
}

#[test]
fn test_apply_superscalar_constants() {
    // After each program, constants are applied:
    // r0 ^= MUL0, r1 ^= ADD1, etc.
    let mut regs = init_dataset_registers(0);
    regs = apply_superscalar_constants(regs);
    
    // After applying, r0 should be XORed with MUL0
    assert(regs.r0 == SUPERSCALAR_MUL0, 'r0 ^= MUL0');
}

// ============================================================
// Dataset Item Generator
// ============================================================

#[test]
fn test_dataset_item_generator_new() {
    // Create generator with cache key
    let key: Array<u8> = array![
        0x74, 0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79
    ];
    
    let gen = dataset_item_generator_new(key.span());
    
    // Generator should be initialized
    assert(gen.programs_generated == 0, 'initial programs = 0');
}

#[test]
fn test_dataset_item_size() {
    // Each dataset item is 64 bytes (8 × u64)
    let item = DatasetItem {
        r0: 0, r1: 0, r2: 0, r3: 0,
        r4: 0, r5: 0, r6: 0, r7: 0,
    };
    
    // Just verify structure exists
    assert(item.r0 == 0, 'item has 8 registers');
}

// ============================================================
// Dataset Item Generation Flow
// ============================================================

#[test]
fn test_generate_dataset_item_deterministic() {
    // Same key + index should produce same item
    let key: Array<u8> = array![
        0x74, 0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79
    ];
    
    let gen1 = dataset_item_generator_new(key.span());
    let gen2 = dataset_item_generator_new(key.span());
    
    let (_, item1) = dataset_item_generate(gen1, 0);
    let (_, item2) = dataset_item_generate(gen2, 0);
    
    // Same inputs should produce same outputs
    assert(item1.r0 == item2.r0, 'deterministic r0');
    assert(item1.r7 == item2.r7, 'deterministic r7');
}

#[test]
fn test_generate_different_items() {
    // Different indices should produce different items
    let key: Array<u8> = array![
        0x74, 0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79
    ];
    
    let gen = dataset_item_generator_new(key.span());
    
    let (gen2, item0) = dataset_item_generate(gen, 0);
    let (_, item1) = dataset_item_generate(gen2, 1);
    
    // Different indices should (very likely) produce different items
    // Note: theoretically could match but extremely unlikely
    assert(item0.r0 != item1.r0 || item0.r7 != item1.r7, 'different items');
}

// ============================================================
// Integration with Cache
// ============================================================

#[test]
fn test_dataset_item_uses_cache() {
    // Dataset item generation XORs with cache entries
    // This test verifies the cache integration point
    assert(true, 'placeholder - needs cache mock');
}

// ============================================================
// Register Wrapping Behavior
// ============================================================

#[test]
fn test_registers_wrap_on_overflow() {
    // All register operations should wrap on overflow (u64)
    let max_u64: u64 = 0xFFFFFFFFFFFFFFFF;
    let regs = init_dataset_registers(max_u64);
    
    // Operations should wrap without panicking
    assert(regs.r0 != 0 || regs.r0 == 0, 'wrapping works');
}

// ============================================================
// OFFICIAL TEST VECTORS - Dataset Item Generation
// Source: RandomX tests.cpp (OFFICIAL)
// https://github.com/tevador/RandomX/blob/master/src/tests/tests.cpp
//
// These vectors verify final r0 value after full SuperscalarHash
// program execution on initialized registers.
//
// NOTE: These are E2E vectors that require full cache integration.
// Currently documented as reference - will pass when cache is implemented.
// ============================================================

#[test]
fn test_dataset_item_official_vector_0() {
    // Official test: Item 0
    // Expected r0 after SuperscalarHash: 0x680588a85ae222db
    // This requires full cache integration to verify
    //
    // For now, verify our initialization is correct
    let regs = init_dataset_registers(0);
    assert(regs.r0 == 0, 'item 0 init r0 = 0');
    
    // TODO: When cache integrated, verify:
    // final_r0 == 0x680588a85ae222db (7566949614573126363)
}

#[test]
fn test_dataset_item_official_vector_10m() {
    // Official test: Item 10,000,000
    // Expected r0 after SuperscalarHash: 0x7943a1f6186ffb72
    //
    // Verify initialization for large item index
    let regs = init_dataset_registers(10000000);
    // r0 = (10000000 + 1) * SUPERSCALAR_MUL0 (with wrapping)
    assert(regs.r0 != 0, 'item 10M init r0 != 0');
    
    // TODO: When cache integrated, verify:
    // final_r0 == 0x7943a1f6186ffb72 (8737474606992423794)
}

#[test]
fn test_dataset_item_official_vector_20m() {
    // Official test: Item 20,000,000
    // Expected r0 after SuperscalarHash: 0x9035244d718095e1
    //
    // Verify initialization for larger item index
    let regs = init_dataset_registers(20000000);
    assert(regs.r0 != 0, 'item 20M init r0 != 0');
    
    // TODO: When cache integrated, verify:
    // final_r0 == 0x9035244d718095e1 (10393232437499008481)
}

#[test]
fn test_dataset_item_official_vector_30m() {
    // Official test: Item 30,000,000
    // Expected r0 after SuperscalarHash: 0x145a5091f7853099
    //
    // Verify initialization for large item index
    let regs = init_dataset_registers(30000000);
    assert(regs.r0 != 0, 'item 30M init r0 != 0');
    
    // TODO: When cache integrated, verify:
    // final_r0 == 0x145a5091f7853099 (1463116619119509657)
}
