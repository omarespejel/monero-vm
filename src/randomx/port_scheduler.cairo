// ============================================================
// ISAP Port Scheduler for SuperscalarHash
// ============================================================
//
// Source: RandomX superscalar.cpp port scheduling
// Reference: https://github.com/tevador/RandomX/blob/master/src/superscalar.cpp
//
// Manages execution port assignment for 3 ports:
// - P0: ALU operations (add, sub, xor, etc.)
// - P1: ALU operations (add, sub, xor, etc.)
// - P5: Multiplication operations only
//
// Port scheduling priority: P5 → P0 → P1
// This ensures multiplications get scheduled first (they have higher latency)
//
// Superscalar width: 3 micro-ops per cycle maximum

use super::prototype::InstructionType;

// ============================================================
// Port Constants
// ============================================================

pub const PORT_P0: u8 = 0;
pub const PORT_P1: u8 = 1;
pub const PORT_P5: u8 = 5;

/// Maximum cycles to track (for cycle bitmap)
const MAX_TRACKED_CYCLES: u32 = 256;

// ============================================================
// Execution Port Enum
// ============================================================

#[derive(Copy, Drop, PartialEq)]
pub enum ExecutionPort {
    P0,
    P1,
    P5,
}

// ============================================================
// Port Scheduler Structure
// Tracks port occupation using cycle counters
// ============================================================

#[derive(Copy, Drop)]
pub struct PortScheduler {
    pub current_cycle: u32,
    // Next free cycle for each port
    pub p0_next_free: u32,
    pub p1_next_free: u32,
    pub p5_next_free: u32,
    // Track recent occupation (simple bitmap for last 64 cycles)
    pub p0_bitmap: u64,
    pub p1_bitmap: u64,
    pub p5_bitmap: u64,
}

// ============================================================
// Port Scheduler Functions
// ============================================================

/// Create new port scheduler with all ports free
pub fn port_scheduler_new() -> PortScheduler {
    PortScheduler {
        current_cycle: 0,
        p0_next_free: 0,
        p1_next_free: 0,
        p5_next_free: 0,
        p0_bitmap: 0,
        p1_bitmap: 0,
        p5_bitmap: 0,
    }
}

/// Check if a port is free at a given cycle
pub fn port_scheduler_is_port_free(scheduler: PortScheduler, port: u8, cycle: u32) -> bool {
    // Check bitmap for recent cycles
    if cycle < 64 {
        let mask: u64 = 1_u64 * pow2_u64(cycle);
        // Use if/else for non-sequential port values (Cairo 2.11 compatibility)
        let bitmap = if port == 0 {
            scheduler.p0_bitmap
        } else if port == 1 {
            scheduler.p1_bitmap
        } else if port == 5 {
            scheduler.p5_bitmap
        } else {
            0
        };
        return (bitmap & mask) == 0;
    }
    
    // For cycles beyond bitmap, check next_free
    let next_free = if port == 0 {
        scheduler.p0_next_free
    } else if port == 1 {
        scheduler.p1_next_free
    } else if port == 5 {
        scheduler.p5_next_free
    } else {
        0
    };
    
    cycle >= next_free
}

/// Schedule an instruction on a port at a specific cycle
pub fn port_scheduler_schedule(
    scheduler: PortScheduler,
    port: u8,
    cycle: u32
) -> PortScheduler {
    let mut new_scheduler = scheduler;
    
    // Update bitmap if cycle is in range
    if cycle < 64 {
        let mask: u64 = 1_u64 * pow2_u64(cycle);
        // Use if/else for non-sequential port values (Cairo 2.11 compatibility)
        if port == 0 {
            new_scheduler.p0_bitmap = scheduler.p0_bitmap | mask;
        } else if port == 1 {
            new_scheduler.p1_bitmap = scheduler.p1_bitmap | mask;
        } else if port == 5 {
            new_scheduler.p5_bitmap = scheduler.p5_bitmap | mask;
        }
    }
    
    // Update next_free if needed
    let new_next_free = cycle + 1;
    if port == 0 {
        if new_next_free > scheduler.p0_next_free {
            new_scheduler.p0_next_free = new_next_free;
        }
    } else if port == 1 {
        if new_next_free > scheduler.p1_next_free {
            new_scheduler.p1_next_free = new_next_free;
        }
    } else if port == 5 {
        if new_next_free > scheduler.p5_next_free {
            new_scheduler.p5_next_free = new_next_free;
        }
    }
    
    new_scheduler
}

/// Get next free cycle for a port starting from given cycle
pub fn port_scheduler_get_next_free_cycle(
    scheduler: PortScheduler,
    port: u8,
    from_cycle: u32
) -> u32 {
    let mut cycle = from_cycle;
    
    // Search for next free cycle (limited search)
    let max_search = from_cycle + 64;
    loop {
        if cycle >= max_search {
            break;
        }
        if port_scheduler_is_port_free(scheduler, port, cycle) {
            return cycle;
        }
        cycle += 1;
    }
    
    // Return max search if not found
    max_search
}

/// Advance scheduler to next cycle
pub fn port_scheduler_advance_cycle(scheduler: PortScheduler) -> PortScheduler {
    PortScheduler {
        current_cycle: scheduler.current_cycle + 1,
        p0_next_free: scheduler.p0_next_free,
        p1_next_free: scheduler.p1_next_free,
        p5_next_free: scheduler.p5_next_free,
        p0_bitmap: scheduler.p0_bitmap,
        p1_bitmap: scheduler.p1_bitmap,
        p5_bitmap: scheduler.p5_bitmap,
    }
}

// ============================================================
// Instruction to Port Mapping
// ============================================================

/// Get the execution port for an instruction type
/// Multiplications use P5, others use P0 or P1
pub fn get_instruction_port(instr_type: InstructionType) -> ExecutionPort {
    match instr_type {
        InstructionType::IMUL_R => ExecutionPort::P5,
        InstructionType::IMULH_R => ExecutionPort::P5,
        InstructionType::ISMULH_R => ExecutionPort::P5,
        InstructionType::IMUL_RCP => ExecutionPort::P5,
        // All others use P0 (primary ALU port)
        _ => ExecutionPort::P0,
    }
}

/// Get instruction latency
pub fn get_instruction_latency(instr_type: InstructionType) -> u32 {
    match instr_type {
        // Multiplications have 3-cycle latency
        InstructionType::IMUL_R => 3,
        InstructionType::IMULH_R => 3,
        InstructionType::ISMULH_R => 3,
        InstructionType::IMUL_RCP => 3,
        // Most ALU ops have 1-cycle latency
        _ => 1,
    }
}

/// Schedule an instruction and return the issue cycle
/// Uses port priority: P5 → P0 → P1
pub fn port_scheduler_schedule_instruction(
    scheduler: PortScheduler,
    instr_type: InstructionType,
    earliest_cycle: u32
) -> (PortScheduler, u32, ExecutionPort) {
    let preferred_port = get_instruction_port(instr_type);
    
    match preferred_port {
        ExecutionPort::P5 => {
            // Multiplications must use P5
            let cycle = port_scheduler_get_next_free_cycle(scheduler, PORT_P5, earliest_cycle);
            let new_scheduler = port_scheduler_schedule(scheduler, PORT_P5, cycle);
            (new_scheduler, cycle, ExecutionPort::P5)
        },
        _ => {
            // ALU ops try P0 first, then P1
            let p0_cycle = port_scheduler_get_next_free_cycle(scheduler, PORT_P0, earliest_cycle);
            let p1_cycle = port_scheduler_get_next_free_cycle(scheduler, PORT_P1, earliest_cycle);
            
            if p0_cycle <= p1_cycle {
                let new_scheduler = port_scheduler_schedule(scheduler, PORT_P0, p0_cycle);
                (new_scheduler, p0_cycle, ExecutionPort::P0)
            } else {
                let new_scheduler = port_scheduler_schedule(scheduler, PORT_P1, p1_cycle);
                (new_scheduler, p1_cycle, ExecutionPort::P1)
            }
        },
    }
}

// ============================================================
// Helper Functions
// ============================================================

fn pow2_u64(exp: u32) -> u64 {
    if exp >= 64 {
        return 0;
    }
    let mut result: u64 = 1;
    let mut i: u32 = 0;
    loop {
        if i == exp {
            break;
        }
        result = result * 2;
        i += 1;
    }
    result
}
