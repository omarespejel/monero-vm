// ============================================================
// Register Allocation Tracker for SuperscalarHash
// ============================================================
//
// Source: RandomX superscalar.cpp register tracking
// Reference: https://github.com/tevador/RandomX/blob/master/src/superscalar.cpp
//
// Tracks register availability for instruction scheduling.
// Each register has an availability cycle - the earliest cycle
// at which it can be used as a destination.
//
// Key constant: LOOK_FORWARD_CYCLES = 4
// This allows scheduling instructions that will have their
// source operand ready within 4 cycles.

// ============================================================
// Constants
// ============================================================

/// Number of cycles to look ahead when checking register availability
/// From RandomX configuration.h
pub const LOOK_FORWARD_CYCLES: u32 = 4;

/// Number of registers in SuperscalarHash
pub const NUM_REGISTERS: u8 = 8;

// ============================================================
// Register Info Structure
// ============================================================

#[derive(Copy, Drop)]
pub struct RegisterInfo {
    pub availability: u32,     // Cycle when register becomes available
    pub last_op_cycle: u32,    // Cycle of last operation using this register
    pub last_op_is_mul: bool,  // Whether last op was multiplication (for chain prevention)
}

// ============================================================
// Register Tracker Structure
// Using individual fields since Cairo doesn't support array indexing
// ============================================================

#[derive(Copy, Drop)]
pub struct RegisterTracker {
    // Availability cycle for each register
    pub r0_avail: u32, pub r1_avail: u32, pub r2_avail: u32, pub r3_avail: u32,
    pub r4_avail: u32, pub r5_avail: u32, pub r6_avail: u32, pub r7_avail: u32,
    // Track if last operation was multiplication (for chain prevention)
    pub r0_mul: bool, pub r1_mul: bool, pub r2_mul: bool, pub r3_mul: bool,
    pub r4_mul: bool, pub r5_mul: bool, pub r6_mul: bool, pub r7_mul: bool,
}

// ============================================================
// Register Tracker Functions
// ============================================================

/// Create new register tracker with all registers available at cycle 0
pub fn register_tracker_new() -> RegisterTracker {
    RegisterTracker {
        r0_avail: 0, r1_avail: 0, r2_avail: 0, r3_avail: 0,
        r4_avail: 0, r5_avail: 0, r6_avail: 0, r7_avail: 0,
        r0_mul: false, r1_mul: false, r2_mul: false, r3_mul: false,
        r4_mul: false, r5_mul: false, r6_mul: false, r7_mul: false,
    }
}

/// Get availability cycle for a register
pub fn register_tracker_get_availability(tracker: RegisterTracker, reg: u8) -> u32 {
    match reg {
        0 => tracker.r0_avail,
        1 => tracker.r1_avail,
        2 => tracker.r2_avail,
        3 => tracker.r3_avail,
        4 => tracker.r4_avail,
        5 => tracker.r5_avail,
        6 => tracker.r6_avail,
        7 => tracker.r7_avail,
        _ => 0,
    }
}

/// Set availability cycle for a register
pub fn register_tracker_set_availability(
    tracker: RegisterTracker,
    reg: u8,
    cycle: u32
) -> RegisterTracker {
    let mut new_tracker = tracker;
    match reg {
        0 => { new_tracker.r0_avail = cycle; },
        1 => { new_tracker.r1_avail = cycle; },
        2 => { new_tracker.r2_avail = cycle; },
        3 => { new_tracker.r3_avail = cycle; },
        4 => { new_tracker.r4_avail = cycle; },
        5 => { new_tracker.r5_avail = cycle; },
        6 => { new_tracker.r6_avail = cycle; },
        7 => { new_tracker.r7_avail = cycle; },
        _ => {},
    }
    new_tracker
}

/// Check if register is available at given cycle
pub fn register_tracker_can_reuse(tracker: RegisterTracker, reg: u8, cycle: u32) -> bool {
    let avail = register_tracker_get_availability(tracker, reg);
    cycle >= avail
}

/// Find an available register at current cycle (with lookahead)
/// Returns None if no register is available
pub fn register_tracker_find_available(
    tracker: RegisterTracker,
    current_cycle: u32
) -> Option<u8> {
    // Check each register, considering LOOK_FORWARD_CYCLES lookahead
    let max_cycle = current_cycle + LOOK_FORWARD_CYCLES;
    
    // First pass: find register available now
    let mut i: u8 = 0;
    loop {
        if i == 8 {
            break;
        }
        let avail = register_tracker_get_availability(tracker, i);
        if avail <= current_cycle {
            return Option::Some(i);
        }
        i += 1;
    }
    
    // Second pass: find register available within lookahead
    let mut j: u8 = 0;
    loop {
        if j == 8 {
            break;
        }
        let avail = register_tracker_get_availability(tracker, j);
        if avail <= max_cycle {
            return Option::Some(j);
        }
        j += 1;
    }
    
    Option::None
}

/// Retire an instruction: update register availability based on latency
pub fn register_tracker_retire(
    tracker: RegisterTracker,
    reg: u8,
    retire_cycle: u32,
    latency: u32
) -> RegisterTracker {
    let new_avail = retire_cycle + latency;
    register_tracker_set_availability(tracker, reg, new_avail)
}

/// Check if register's last operation was multiplication
pub fn register_tracker_is_mul_output(tracker: RegisterTracker, reg: u8) -> bool {
    match reg {
        0 => tracker.r0_mul,
        1 => tracker.r1_mul,
        2 => tracker.r2_mul,
        3 => tracker.r3_mul,
        4 => tracker.r4_mul,
        5 => tracker.r5_mul,
        6 => tracker.r6_mul,
        7 => tracker.r7_mul,
        _ => false,
    }
}

/// Set register's multiplication flag
pub fn register_tracker_set_mul_flag(
    tracker: RegisterTracker,
    reg: u8,
    is_mul: bool
) -> RegisterTracker {
    let mut new_tracker = tracker;
    match reg {
        0 => { new_tracker.r0_mul = is_mul; },
        1 => { new_tracker.r1_mul = is_mul; },
        2 => { new_tracker.r2_mul = is_mul; },
        3 => { new_tracker.r3_mul = is_mul; },
        4 => { new_tracker.r4_mul = is_mul; },
        5 => { new_tracker.r5_mul = is_mul; },
        6 => { new_tracker.r6_mul = is_mul; },
        7 => { new_tracker.r7_mul = is_mul; },
        _ => {},
    }
    new_tracker
}

/// Find available register excluding those with pending multiplication output
/// This prevents chained multiplications which have high latency
pub fn register_tracker_find_available_non_mul(
    tracker: RegisterTracker,
    current_cycle: u32
) -> Option<u8> {
    let max_cycle = current_cycle + LOOK_FORWARD_CYCLES;
    
    // Find register that is available and not a mul output
    let mut i: u8 = 0;
    loop {
        if i == 8 {
            break;
        }
        let avail = register_tracker_get_availability(tracker, i);
        let is_mul = register_tracker_is_mul_output(tracker, i);
        
        if avail <= max_cycle && !is_mul {
            return Option::Some(i);
        }
        i += 1;
    }
    
    Option::None
}
