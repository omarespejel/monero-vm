// ============================================================
// TDD Tests for Register Allocation Tracker
// Source: RandomX superscalar.cpp - register tracking
// ============================================================
//
// The register tracker manages:
// 1. Register availability (when each register becomes free)
// 2. Last-use tracking for dependency detection
// 3. LOOK_FORWARD_CYCLES = 4 lookahead for scheduling

use monero_vm::randomx::register_tracker::{
    register_tracker_new, register_tracker_get_availability,
    register_tracker_set_availability, register_tracker_find_available,
    register_tracker_can_reuse, register_tracker_retire,
    LOOK_FORWARD_CYCLES,
};

// ============================================================
// Constants
// ============================================================

#[test]
fn test_look_forward_cycles_is_4() {
    // RandomX uses 4-cycle lookahead for register scheduling
    assert(LOOK_FORWARD_CYCLES == 4, 'LOOK_FORWARD = 4');
}

// ============================================================
// Register Tracker Initialization
// ============================================================

#[test]
fn test_register_tracker_new() {
    // Create tracker for 8 registers
    let _tracker = register_tracker_new();
    
    // All registers should be available at cycle 0 initially
    assert(register_tracker_get_availability(_tracker, 0) == 0, 'r0 avail at 0');
    assert(register_tracker_get_availability(_tracker, 7) == 0, 'r7 avail at 0');
}

#[test]
fn test_register_tracker_8_registers() {
    // SuperscalarHash uses 8 integer registers (r0-r7)
    let _tracker = register_tracker_new();
    
    // All 8 registers should be accessible
    let mut i: u8 = 0;
    loop {
        if i == 8 {
            break;
        }
        let avail = register_tracker_get_availability(_tracker, i);
        assert(avail == 0, 'register available');
        i += 1;
    }
}

// ============================================================
// Register Availability Tracking
// ============================================================

#[test]
fn test_set_availability() {
    // Set register availability to future cycle
    let mut tracker = register_tracker_new();
    
    // r0 becomes available at cycle 5
    tracker = register_tracker_set_availability(tracker, 0, 5);
    
    assert(register_tracker_get_availability(tracker, 0) == 5, 'r0 at cycle 5');
    // Other registers unchanged
    assert(register_tracker_get_availability(tracker, 1) == 0, 'r1 unchanged');
}

#[test]
fn test_availability_multiple_registers() {
    // Set different availability for each register
    let mut tracker = register_tracker_new();
    
    tracker = register_tracker_set_availability(tracker, 0, 3);
    tracker = register_tracker_set_availability(tracker, 1, 5);
    tracker = register_tracker_set_availability(tracker, 2, 7);
    
    assert(register_tracker_get_availability(tracker, 0) == 3, 'r0 at 3');
    assert(register_tracker_get_availability(tracker, 1) == 5, 'r1 at 5');
    assert(register_tracker_get_availability(tracker, 2) == 7, 'r2 at 7');
}

// ============================================================
// Find Available Register
// ============================================================

#[test]
fn test_find_available_all_free() {
    // When all registers are free, should find one
    let tracker = register_tracker_new();
    let current_cycle: u32 = 0;
    
    let result = register_tracker_find_available(tracker, current_cycle);
    
    // Should find a register (any of r0-r7)
    assert(result.is_some(), 'should find register');
    let reg = result.unwrap();
    assert(reg < 8, 'valid register');
}

#[test]
fn test_find_available_some_busy() {
    // With some registers busy, should find a free one
    let mut tracker = register_tracker_new();
    let current_cycle: u32 = 0;
    
    // Mark r0-r5 as busy until cycle 10
    tracker = register_tracker_set_availability(tracker, 0, 10);
    tracker = register_tracker_set_availability(tracker, 1, 10);
    tracker = register_tracker_set_availability(tracker, 2, 10);
    tracker = register_tracker_set_availability(tracker, 3, 10);
    tracker = register_tracker_set_availability(tracker, 4, 10);
    tracker = register_tracker_set_availability(tracker, 5, 10);
    
    let result = register_tracker_find_available(tracker, current_cycle);
    
    // Should find r6 or r7
    assert(result.is_some(), 'should find register');
    let reg = result.unwrap();
    assert(reg >= 6, 'should be r6 or r7');
}

#[test]
fn test_find_available_none_free() {
    // When all registers are busy, should return None
    let mut tracker = register_tracker_new();
    let current_cycle: u32 = 0;
    
    // Mark all registers as busy until cycle 10
    let mut i: u8 = 0;
    loop {
        if i == 8 {
            break;
        }
        tracker = register_tracker_set_availability(tracker, i, 10);
        i += 1;
    }
    
    let result = register_tracker_find_available(tracker, current_cycle);
    
    // Should not find any register
    assert(result.is_none(), 'no register available');
}

#[test]
fn test_find_available_with_lookahead() {
    // With LOOK_FORWARD_CYCLES=4, can use register that becomes free within 4 cycles
    let mut tracker = register_tracker_new();
    let current_cycle: u32 = 5;
    
    // r0 becomes available at cycle 8 (within lookahead of cycle 5)
    tracker = register_tracker_set_availability(tracker, 0, 8);
    // All others busy until cycle 20
    tracker = register_tracker_set_availability(tracker, 1, 20);
    tracker = register_tracker_set_availability(tracker, 2, 20);
    tracker = register_tracker_set_availability(tracker, 3, 20);
    tracker = register_tracker_set_availability(tracker, 4, 20);
    tracker = register_tracker_set_availability(tracker, 5, 20);
    tracker = register_tracker_set_availability(tracker, 6, 20);
    tracker = register_tracker_set_availability(tracker, 7, 20);
    
    let result = register_tracker_find_available(tracker, current_cycle);
    
    // Should find r0 (available within lookahead)
    assert(result.is_some(), 'should find with lookahead');
    assert(result.unwrap() == 0, 'should be r0');
}

// ============================================================
// Register Retirement (after instruction completes)
// ============================================================

#[test]
fn test_retire_updates_availability() {
    // After instruction retires, register becomes available
    let mut tracker = register_tracker_new();
    
    // r0 was busy, instruction retires at cycle 10 with latency 3
    tracker = register_tracker_set_availability(tracker, 0, 10);
    tracker = register_tracker_retire(tracker, 0, 10, 3);
    
    // r0 now available at cycle 13 (retire_cycle + latency)
    assert(register_tracker_get_availability(tracker, 0) == 13, 'r0 avail at 13');
}

// ============================================================
// Dependency Detection
// ============================================================

#[test]
fn test_can_reuse_after_available() {
    // Can reuse register after it becomes available
    let mut tracker = register_tracker_new();
    
    tracker = register_tracker_set_availability(tracker, 0, 5);
    
    // At cycle 5, r0 is available
    assert(register_tracker_can_reuse(tracker, 0, 5), 'can reuse at 5');
    // At cycle 6, definitely available
    assert(register_tracker_can_reuse(tracker, 0, 6), 'can reuse at 6');
}

#[test]
fn test_cannot_reuse_before_available() {
    // Cannot reuse register before it becomes available
    let mut tracker = register_tracker_new();
    
    tracker = register_tracker_set_availability(tracker, 0, 5);
    
    // At cycle 4, r0 is not yet available
    assert(!register_tracker_can_reuse(tracker, 0, 4), 'cannot reuse at 4');
}

// ============================================================
// Multiplication Tracking (for chained mul prevention)
// ============================================================

#[test]
fn test_track_multiplication_output() {
    // Track which register received multiplication output
    // This is needed to prevent chained multiplications
    let _tracker = register_tracker_new();
    
    // This functionality will be added to the tracker
    assert(true, 'placeholder');
}
