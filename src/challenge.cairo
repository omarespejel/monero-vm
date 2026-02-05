/// MoneroVM Challenge Contract
/// 
/// Handles fraud proof disputes for RandomX verification.
/// Inspired by BitVM and Arbitrum's optimistic verification patterns.

use starknet::ContractAddress;

// Re-export register types for InstructionProof struct
pub use crate::randomx::fraud_proof::IntegerRegisters;
pub use crate::randomx::fraud_proof::{FloatRegister, FloatRegisters};

/// Instruction opcodes for RandomX
/// Reference: https://github.com/tevador/RandomX/blob/master/src/instruction.hpp
pub mod opcodes {
    // Integer register instructions (0-10)
    pub const IADD_R: u8 = 0;
    pub const ISUB_R: u8 = 1;
    pub const IMUL_R: u8 = 2;
    pub const IMULH_R: u8 = 3;
    pub const ISMULH_R: u8 = 4;
    pub const IMUL_RCP: u8 = 5;
    pub const IXOR_R: u8 = 6;
    pub const IROR_R: u8 = 7;
    pub const IROL_R: u8 = 8;
    pub const ISWAP_R: u8 = 9;
    
    // CRITICAL: INEG_R = 11 (Per spec, frequency 2/256)
    pub const INEG_R: u8 = 11;
    
    // Memory instructions (12-17)
    pub const IADD_M: u8 = 12;
    pub const ISUB_M: u8 = 13;
    pub const IMUL_M: u8 = 14;
    pub const IMULH_M: u8 = 15;
    pub const ISMULH_M: u8 = 16;
    pub const IXOR_M: u8 = 17;
    
    // Shift with displacement
    pub const IADD_RS: u8 = 18;
    
    // FP instructions (20-28)
    pub const FADD_R: u8 = 20;
    pub const FADD_M: u8 = 21;
    pub const FSUB_R: u8 = 22;
    pub const FSUB_M: u8 = 23;
    pub const FMUL_R: u8 = 24;
    pub const FDIV_M: u8 = 25;
    pub const FSQRT_R: u8 = 26;
    pub const FSCAL_R: u8 = 27;
    pub const CFROUND: u8 = 28;
    
    // NOP and control flow
    pub const NOP: u8 = 29;
    pub const CBRANCH: u8 = 30;
    pub const ISTORE: u8 = 31;
    
    // Configuration constants from RandomX
    /// StoreL3Condition: mod_cond >= 14 triggers L3 for ISTORE
    /// Reference: configuration.h
    pub const STORE_L3_CONDITION: u8 = 14;
    
    /// Register that needs displacement (r5)
    pub const REGISTER_NEEDS_DISPLACEMENT: u8 = 5;
}

/// Challenge status enum
#[derive(Drop, Copy, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum ChallengeStatus {
    /// No active challenge
    None,
    /// Challenge opened, awaiting defender response
    Open,
    /// In bisection phase
    Bisecting,
    /// Awaiting final proof
    AwaitingProof,
    /// Challenge resolved in favor of challenger
    ChallengerWon,
    /// Challenge resolved in favor of defender
    DefenderWon,
    /// Challenge timed out
    TimedOut,
}

/// Bisection state for narrowing down disputed instruction
#[derive(Drop, Copy, Serde, starknet::Store)]
pub struct BisectionState {
    /// Left bound of disputed range
    pub left: u32,
    /// Right bound of disputed range
    pub right: u32,
    /// Current bisection round
    pub round: u8,
    /// Whose turn to respond (true = challenger, false = defender)
    pub challenger_turn: bool,
    /// Challenger's claimed midpoint state hash for current round
    pub challenger_midpoint: felt252,
    /// Defender's claimed midpoint state hash for current round
    pub defender_midpoint: felt252,
    /// Whether challenger has submitted this round
    pub challenger_submitted: bool,
    /// Whether defender has submitted this round
    pub defender_submitted: bool,
}

/// Challenge data stored on-chain
#[derive(Drop, Copy, Serde, starknet::Store)]
pub struct Challenge {
    /// Unique challenge ID
    pub id: u64,
    /// Challenger address
    pub challenger: ContractAddress,
    /// Defender address (original claimer)
    pub defender: ContractAddress,
    /// Current status
    pub status: ChallengeStatus,
    /// Challenger's claimed final hash
    pub challenger_hash: felt252,
    /// Defender's claimed final hash
    pub defender_hash: felt252,
    /// Challenger's execution trace root (Merkle root of all states)
    pub challenger_trace_root: felt252,
    /// Defender's execution trace root
    pub defender_trace_root: felt252,
    /// Bisection state
    pub bisection: BisectionState,
    /// Challenge creation timestamp
    pub created_at: u64,
    /// Last action timestamp
    pub last_action_at: u64,
    /// Challenger bond amount
    pub challenger_bond: u256,
    /// Defender bond amount
    pub defender_bond: u256,
}

/// Instruction proof for single instruction dispute resolution
#[derive(Drop, Copy, Serde)]
pub struct InstructionProof {
    /// Instruction opcode (see opcodes module)
    pub opcode: u8,
    /// Destination register index (0-7)
    pub dst_idx: u8,
    /// Source register index (0-7)
    pub src_idx: u8,
    /// Immediate value (for memory instructions, IADD_RS r5)
    pub imm32: u32,
    /// Shift amount (for IADD_RS)
    pub shift: u8,
    /// Pre-execution state hash
    pub pre_state_hash: felt252,
    /// Post-execution state hash (claimed)
    pub post_state_hash: felt252,
    /// Pre-execution integer registers (actual values for verification)
    pub pre_regs: IntegerRegisters,
    /// Post-execution integer registers (claimed by prover)
    pub post_regs: IntegerRegisters,
    
    // ========================================================================
    // Memory instruction fields (opcodes 12-17, 31)
    // Required for Merkle-verified memory operations
    // ========================================================================
    
    /// Scratchpad Merkle root before instruction execution
    pub scratchpad_root: felt252,
    /// Memory witness: value at computed address
    pub mem_value: u64,
    /// Memory witness: Merkle proof length
    pub mem_proof_len: u8,
    /// Memory witness: Merkle proof siblings (15 elements for 2MB scratchpad)
    pub mem_proof_0: felt252,
    pub mem_proof_1: felt252,
    pub mem_proof_2: felt252,
    pub mem_proof_3: felt252,
    pub mem_proof_4: felt252,
    pub mem_proof_5: felt252,
    pub mem_proof_6: felt252,
    pub mem_proof_7: felt252,
    pub mem_proof_8: felt252,
    pub mem_proof_9: felt252,
    pub mem_proof_10: felt252,
    pub mem_proof_11: felt252,
    pub mem_proof_12: felt252,
    pub mem_proof_13: felt252,
    pub mem_proof_14: felt252,
    
    // ========================================================================
    // ISTORE-specific fields (opcode 31)
    // ========================================================================
    
    /// mod.cond value for scratchpad level selection (also used for CBRANCH)
    pub mod_cond: u8,
    /// mod.mem value for L1/L2 selection
    pub mod_mem: u8,
    /// Old value at store address (for Merkle proof verification)
    pub store_old_value: u64,
    /// Post-execution scratchpad root (after store)
    pub post_scratchpad_root: felt252,
    
    // ========================================================================
    // CBRANCH-specific fields (opcode 30)
    // Required for register modification tracking and jump verification
    // ========================================================================
    
    /// Constructed immediate for CBRANCH (signed, from imm32 + condition bits)
    /// Stored as two u64 values to represent i64: low bits and sign flag
    pub cimm_low: u64,
    /// Sign of cimm: 0 = positive, 1 = negative
    pub cimm_sign: u8,
    /// PC when destination register was last modified
    pub last_modified_pc: u32,
    /// Whether the conditional branch was taken
    pub jump_taken: bool,
    /// New program counter after CBRANCH (target if taken, PC+1 if not)
    pub new_pc: u32,
    /// Current program counter (before CBRANCH execution)
    pub current_pc: u32,
    
    // Register modification tracker: PC when each register was last modified
    // Value of 0xFFFFFFFF means "never modified"
    pub r0_last_mod: u32,
    pub r1_last_mod: u32,
    pub r2_last_mod: u32,
    pub r3_last_mod: u32,
    pub r4_last_mod: u32,
    pub r5_last_mod: u32,
    pub r6_last_mod: u32,
    pub r7_last_mod: u32,
    
    // ========================================================================
    // Floating-point instruction fields (opcodes 20-28)
    // Required for IEEE-754 verification with witness-based proofs
    // ========================================================================
    
    /// Pre-execution floating-point registers (F-group f0-f3, E-group e0-e3, A-group a0-a3)
    pub pre_float_regs: FloatRegisters,
    /// Post-execution floating-point registers (claimed by prover)
    pub post_float_regs: FloatRegisters,
    
    /// Floating-point rounding control (0-3 per IEEE-754 rounding modes)
    /// 0 = roundToNearest, 1 = roundDown, 2 = roundUp, 3 = roundToZero
    pub fprc: u8,
    
    /// E-mask for E-group masking (FDIV_M, iteration start)
    /// Contains exponent mask (bits 52-62) and mantissa mask (bits 0-21)
    pub e_mask: u64,
    
    // FP Witness data for complex operations (FADD, FMUL, FDIV, FSQRT)
    // Provides intermediate values that can be verified with integer arithmetic
    
    /// Extended mantissa high bits (for intermediate computation)
    pub fp_witness_mantissa_hi: u64,
    /// Extended mantissa low bits
    pub fp_witness_mantissa_lo: u64,
    /// Rounding adjustment applied (0-2)
    pub fp_witness_rounding_adj: u8,
    /// Guard/Round/Sticky bits packed: (guard*4 + round*2 + sticky)
    pub fp_witness_grs: u8,
    /// Alignment shift for addition/subtraction
    pub fp_witness_shift: u8,
    /// Result sign (0 = positive, 1 = negative)
    pub fp_witness_result_sign: u8,
    /// Result exponent before normalization
    pub fp_witness_exponent: i16,
    /// Normalization shift (leading zeros)
    pub fp_witness_norm_shift: u8,
    /// Is subtraction operation
    pub fp_witness_is_sub: u8,
    
    // Second witness for 128-bit register operations (lo and hi lanes)
    pub fp_witness2_mantissa_hi: u64,
    pub fp_witness2_mantissa_lo: u64,
    pub fp_witness2_rounding_adj: u8,
    pub fp_witness2_grs: u8,
    pub fp_witness2_shift: u8,
    pub fp_witness2_result_sign: u8,
    pub fp_witness2_exponent: i16,
    pub fp_witness2_norm_shift: u8,
    pub fp_witness2_is_sub: u8,
    
    // E-mask source entropy for validation
    /// Program entropy value used to compute e_mask
    /// Verifier computes: e_mask_expected = compute_e_mask(e_mask_entropy)
    pub e_mask_entropy: u64,
}

/// Contract interface
#[starknet::interface]
pub trait IChallengeContract<TContractState> {
    /// Open a new challenge against a RandomX claim
    fn open_challenge(
        ref self: TContractState,
        defender: ContractAddress,
        defender_hash: felt252,
        defender_trace_root: felt252,
        challenger_hash: felt252,
        challenger_trace_root: felt252,
    ) -> u64;
    
    /// Defender responds to challenge by posting their trace root
    fn defend(
        ref self: TContractState,
        challenge_id: u64,
    );
    
    /// Submit bisection move (both parties)
    fn bisect(
        ref self: TContractState,
        challenge_id: u64,
        midpoint_state_hash: felt252,
        merkle_proof: Span<felt252>,
    );
    
    /// Submit final proof for single instruction
    fn submit_proof(
        ref self: TContractState,
        challenge_id: u64,
        proof: InstructionProof,
    );
    
    /// Claim timeout victory
    fn claim_timeout(
        ref self: TContractState,
        challenge_id: u64,
    );
    
    /// Get challenge details
    fn get_challenge(self: @TContractState, challenge_id: u64) -> Challenge;
    
    /// Get current challenge count
    fn get_challenge_count(self: @TContractState) -> u64;
}

#[starknet::contract]
pub mod ChallengeContract {
    use super::{Challenge, ChallengeStatus, BisectionState, IChallengeContract};
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess,
        StoragePointerReadAccess, StoragePointerWriteAccess
    };
    use core::poseidon::poseidon_hash_span;
    
    /// Contract constants
    pub mod constants {
        /// Challenger bond in wei (0.1 ETH equivalent)
        pub const CHALLENGER_BOND: u256 = 100000000000000000;
        
        /// Defender bond in wei (0.2 ETH equivalent)
        pub const DEFENDER_BOND: u256 = 200000000000000000;
        
        /// Bisection timeout in seconds (4 hours)
        pub const BISECTION_TIMEOUT: u64 = 14400;
        
        /// Final proof timeout in seconds (24 hours)
        pub const FINAL_PROOF_TIMEOUT: u64 = 86400;
        
        /// Total bisection rounds for MVP (8 rounds for 256 instructions)
        pub const MVP_BISECTION_ROUNDS: u8 = 8;
    }
    
    #[storage]
    struct Storage {
        /// Challenge counter
        challenge_count: u64,
        /// Challenge storage by ID
        challenges: Map<u64, Challenge>,
        /// Owner address
        owner: ContractAddress,
        /// Replay protection: maps claim_hash → active challenge_id
        /// Prevents duplicate challenges on the same claim
        active_challenges_for_claim: Map<felt252, u64>,
    }
    
    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ChallengeOpened: ChallengeOpened,
        ChallengeDefended: ChallengeDefended,
        BisectionMove: BisectionMove,
        ChallengeResolved: ChallengeResolved,
        DeferredVerificationDispute: DeferredVerificationDispute,
    }
    
    #[derive(Drop, starknet::Event)]
    pub struct ChallengeOpened {
        #[key]
        pub challenge_id: u64,
        pub challenger: ContractAddress,
        pub defender: ContractAddress,
    }
    
    #[derive(Drop, starknet::Event)]
    pub struct ChallengeDefended {
        #[key]
        pub challenge_id: u64,
    }
    
    #[derive(Drop, starknet::Event)]
    pub struct BisectionMove {
        #[key]
        pub challenge_id: u64,
        pub round: u8,
        pub new_left: u32,
        pub new_right: u32,
    }
    
    #[derive(Drop, starknet::Event)]
    pub struct ChallengeResolved {
        #[key]
        pub challenge_id: u64,
        pub winner: ContractAddress,
        pub status: ChallengeStatus,
    }
    
    /// Emitted when a dispute involves deferred verification (FP, memory, control flow)
    /// Per spec recommendation: Monitor frequency for governance escalation threshold
    /// Threshold suggestion: If challenger_bond + defender_bond > 1 ETH, consider governance
    #[derive(Drop, starknet::Event)]
    pub struct DeferredVerificationDispute {
        #[key]
        pub challenge_id: u64,
        /// Type of deferred verification: 0=FP, 1=Memory, 2=ControlFlow
        pub dispute_type: u8,
        /// Opcode that triggered deferred verification
        pub opcode: u8,
        /// Winner (defender in all deferred cases)
        pub winner: ContractAddress,
    }
    
    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
        self.challenge_count.write(0);
    }
    
    #[abi(embed_v0)]
    impl ChallengeContractImpl of IChallengeContract<ContractState> {
        fn open_challenge(
            ref self: ContractState,
            defender: ContractAddress,
            defender_hash: felt252,
            defender_trace_root: felt252,
            challenger_hash: felt252,
            challenger_trace_root: felt252,
        ) -> u64 {
            let caller = get_caller_address();
            let timestamp = get_block_timestamp();
            
            // Compute claim hash for replay protection
            // A claim is uniquely identified by: defender + their claimed hash + trace root
            let claim_hash = core::poseidon::poseidon_hash_span(
                array![defender.into(), defender_hash, defender_trace_root].span()
            );
            
            // Check for existing active challenge on this claim
            let existing_challenge_id = self.active_challenges_for_claim.read(claim_hash);
            if existing_challenge_id != 0 {
                let existing = self.challenges.read(existing_challenge_id);
                // Only block if challenge is still active (Open or Bisecting)
                let is_active = existing.status == ChallengeStatus::Open 
                    || existing.status == ChallengeStatus::Bisecting
                    || existing.status == ChallengeStatus::AwaitingProof;
                assert(!is_active, 'Claim already being challenged');
            }
            
            // Increment challenge counter
            let challenge_id = self.challenge_count.read() + 1;
            self.challenge_count.write(challenge_id);
            
            // Create initial bisection state (full program range)
            let bisection = BisectionState {
                left: 0,
                right: 256,  // 256 instructions per program
                round: 0,
                challenger_turn: false,  // Both can submit, order doesn't matter
                challenger_midpoint: 0,
                defender_midpoint: 0,
                challenger_submitted: false,
                defender_submitted: false,
            };
            
            // Create challenge
            let challenge = Challenge {
                id: challenge_id,
                challenger: caller,
                defender,
                status: ChallengeStatus::Open,
                challenger_hash,
                defender_hash,
                challenger_trace_root,
                defender_trace_root,
                bisection,
                created_at: timestamp,
                last_action_at: timestamp,
                challenger_bond: constants::CHALLENGER_BOND,
                defender_bond: 0,  // Defender hasn't bonded yet
            };
            
            // Store challenge
            self.challenges.write(challenge_id, challenge);
            
            // Store replay protection mapping
            self.active_challenges_for_claim.write(claim_hash, challenge_id);
            
            // Emit event
            self.emit(ChallengeOpened { challenge_id, challenger: caller, defender });
            
            challenge_id
        }
        
        fn defend(
            ref self: ContractState,
            challenge_id: u64,
        ) {
            let caller = get_caller_address();
            let timestamp = get_block_timestamp();
            let mut challenge = self.challenges.read(challenge_id);
            
            // Verify caller is defender
            assert(caller == challenge.defender, 'Only defender can respond');
            
            // Verify challenge is open
            assert(challenge.status == ChallengeStatus::Open, 'Challenge not open');
            
            // Update challenge status
            challenge.status = ChallengeStatus::Bisecting;
            challenge.defender_bond = constants::DEFENDER_BOND;
            challenge.last_action_at = timestamp;
            
            // Store updated challenge
            self.challenges.write(challenge_id, challenge);
            
            // Emit event
            self.emit(ChallengeDefended { challenge_id });
        }
        
        fn bisect(
            ref self: ContractState,
            challenge_id: u64,
            midpoint_state_hash: felt252,
            merkle_proof: Span<felt252>,
        ) {
            let caller = get_caller_address();
            let timestamp = get_block_timestamp();
            let mut challenge = self.challenges.read(challenge_id);
            
            // Verify challenge is in bisection phase
            assert(challenge.status == ChallengeStatus::Bisecting, 'Not in bisection');
            
            // Identify caller as challenger or defender
            let is_challenger = caller == challenge.challenger;
            let is_defender = caller == challenge.defender;
            assert(is_challenger || is_defender, 'Not a party to challenge');
            
            // Check if caller already submitted this round
            if is_challenger {
                assert(!challenge.bisection.challenger_submitted, 'Already submitted');
            } else {
                assert(!challenge.bisection.defender_submitted, 'Already submitted');
            }
            
            // Verify Merkle proof for midpoint state
            let midpoint = (challenge.bisection.left + challenge.bisection.right) / 2;
            let trace_root = if is_challenger {
                challenge.challenger_trace_root
            } else {
                challenge.defender_trace_root
            };
            
            // PRT security: verify claimed state is consistent with trace root
            assert(
                verify_merkle_proof(trace_root, midpoint, midpoint_state_hash, merkle_proof),
                'Invalid Merkle proof'
            );
            
            // Store this party's midpoint claim
            if is_challenger {
                challenge.bisection.challenger_midpoint = midpoint_state_hash;
                challenge.bisection.challenger_submitted = true;
            } else {
                challenge.bisection.defender_midpoint = midpoint_state_hash;
                challenge.bisection.defender_submitted = true;
            }
            
            challenge.last_action_at = timestamp;
            
            // Check if both parties have submitted
            if challenge.bisection.challenger_submitted && challenge.bisection.defender_submitted {
                // Both submitted - determine disagreement and advance round
                let new_round = challenge.bisection.round + 1;
                
                // Per spec: proper disagreement detection
                // If midpoint hashes differ → dispute is in left half (before midpoint)
                // If midpoint hashes agree → dispute is in right half (after midpoint)
                if challenge.bisection.challenger_midpoint != challenge.bisection.defender_midpoint {
                    // Disagree at midpoint → narrow to left half [left, midpoint]
                    challenge.bisection.right = midpoint;
                } else {
                    // Agree at midpoint → narrow to right half [midpoint, right]
                    challenge.bisection.left = midpoint;
                }
                
                // Reset submission flags for next round
                challenge.bisection.challenger_submitted = false;
                challenge.bisection.defender_submitted = false;
                challenge.bisection.challenger_midpoint = 0;
                challenge.bisection.defender_midpoint = 0;
                challenge.bisection.round = new_round;
                
                // Check if we've reached single instruction
                if new_round >= constants::MVP_BISECTION_ROUNDS {
                    challenge.status = ChallengeStatus::AwaitingProof;
                }
                
                // Store updated challenge BEFORE emitting event
                self.challenges.write(challenge_id, challenge);
                
                // Emit event after successful write
                self.emit(BisectionMove {
                    challenge_id,
                    round: new_round,
                    new_left: challenge.bisection.left,
                    new_right: challenge.bisection.right,
                });
            } else {
                // Only one party submitted, waiting for the other
                self.challenges.write(challenge_id, challenge);
            }
        }
        
        fn submit_proof(
            ref self: ContractState,
            challenge_id: u64,
            proof: super::InstructionProof,
        ) {
            let caller = get_caller_address();
            let timestamp = get_block_timestamp();
            let mut challenge = self.challenges.read(challenge_id);
            
            // Verify challenge is awaiting proof
            assert(challenge.status == ChallengeStatus::AwaitingProof, 'Not awaiting proof');
            
            // Verify caller is participant
            let is_challenger = caller == challenge.challenger;
            let is_defender = caller == challenge.defender;
            assert(is_challenger || is_defender, 'Not a participant');
            
            // Verify instruction using the appropriate verifier
            // Returns VerificationResult which determines winner:
            // - Verified: Prover wins
            // - Rejected: Prover loses (fraud detected)
            // - FPStubRejection: Defender wins (can't prove fraud without FP verification)
            // - MemoryVerificationDeferred: Defender wins (Merkle witness not yet integrated)
            // - ControlFlowVerificationDeferred: Defender wins (full state not yet integrated)
            // - InvalidProof: Prover loses
            let verification_result = verify_instruction_proof(proof);
            
            // Emit event for deferred verification (for monitoring per spec recommendation)
            // This helps track disputes that can't be fully verified
            let dispute_type = get_deferred_dispute_type(verification_result);
            if dispute_type != 255_u8 {  // 255 = not deferred
                self.emit(DeferredVerificationDispute {
                    challenge_id,
                    dispute_type,
                    opcode: proof.opcode,
                    winner: challenge.defender,  // Defender always wins in deferred cases
                });
            }
            
            // Determine winner based on verification result
            // Per spec: FP stub rejection → Defender wins
            let winner = resolve_dispute(
                verification_result,
                is_challenger,
                challenge.challenger,
                challenge.defender
            );
            
            challenge.status = if winner == challenge.challenger {
                ChallengeStatus::ChallengerWon
            } else {
                ChallengeStatus::DefenderWon
            };
            challenge.last_action_at = timestamp;
            
            // Emit event
            self.emit(ChallengeResolved {
                challenge_id,
                winner,
                status: challenge.status,
            });
            
            // Store updated challenge
            self.challenges.write(challenge_id, challenge);
        }
        
        fn claim_timeout(
            ref self: ContractState,
            challenge_id: u64,
        ) {
            let _caller = get_caller_address();
            let timestamp = get_block_timestamp();
            let mut challenge = self.challenges.read(challenge_id);
            
            // Verify challenge is active
            assert(
                challenge.status == ChallengeStatus::Open
                || challenge.status == ChallengeStatus::Bisecting
                || challenge.status == ChallengeStatus::AwaitingProof,
                'Challenge not active'
            );
            
            // Calculate timeout based on phase
            let timeout = if challenge.status == ChallengeStatus::AwaitingProof {
                constants::FINAL_PROOF_TIMEOUT
            } else {
                constants::BISECTION_TIMEOUT
            };
            
            // Verify timeout has occurred
            assert(timestamp > challenge.last_action_at + timeout, 'Timeout not reached');
            
            // Determine winner based on whose turn it was
            let winner = if challenge.status == ChallengeStatus::Open {
                // Defender didn't respond
                challenge.challenger
            } else if challenge.bisection.challenger_turn {
                // Challenger timed out
                challenge.defender
            } else {
                // Defender timed out
                challenge.challenger
            };
            
            challenge.status = ChallengeStatus::TimedOut;
            challenge.last_action_at = timestamp;
            
            // Emit event
            self.emit(ChallengeResolved {
                challenge_id,
                winner,
                status: challenge.status,
            });
            
            // Store updated challenge
            self.challenges.write(challenge_id, challenge);
        }
        
        fn get_challenge(self: @ContractState, challenge_id: u64) -> Challenge {
            self.challenges.read(challenge_id)
        }
        
        fn get_challenge_count(self: @ContractState) -> u64 {
            self.challenge_count.read()
        }
    }
    
    /// Verify Merkle proof for state at given instruction index
    fn verify_merkle_proof(
        root: felt252,
        index: u32,
        claimed_hash: felt252,
        proof: Span<felt252>
    ) -> bool {
        let mut current_hash = claimed_hash;
        let mut current_index = index;
        let mut i: u32 = 0;
        
        loop {
            if i >= proof.len() {
                break;
            }
            
            let sibling = *proof.at(i);
            
            if current_index % 2 == 0 {
                current_hash = poseidon_hash_span(array![current_hash, sibling].span());
            } else {
                current_hash = poseidon_hash_span(array![sibling, current_hash].span());
            }
            
            current_index = current_index / 2;
            i += 1;
        };
        
        current_hash == root
    }
    
    /// Verification result enum
    /// Per spec recommendation: FP stub rejection should favor defender
    #[derive(Drop, Copy, PartialEq)]
    enum VerificationResult {
        /// Proof verified successfully - prover wins
        Verified,
        /// Proof rejected (fraud proven) - challenger wins if they submitted proof
        Rejected,
        /// FP instruction but verification not implemented - defender wins
        /// Rationale: Can't prove fraud without full verification
        FPStubRejection,
        /// Memory instruction verification deferred - defender wins
        /// Per spec: Memory verifiers require Merkle proofs not yet integrated
        /// Rationale: Can't verify memory correctness without witness data
        MemoryVerificationDeferred,
        /// Control flow instruction (CBRANCH/ISTORE) verification deferred - defender wins
        /// Per spec: These require additional state (branch target, scratchpad updates)
        ControlFlowVerificationDeferred,
        /// Invalid proof structure
        InvalidProof,
    }
    
    /// Check if an opcode is a floating-point instruction
    fn is_fp_instruction(opcode: u8) -> bool {
        // FP opcodes: FADD_R=20, FADD_M=21, FSUB_R=22, FSUB_M=23, FMUL_R=24, FDIV_M=25, FSQRT_R=26, FSCAL_R=27, CFROUND=28
        opcode >= 20 && opcode <= 28
    }
    
    /// Check if an opcode is a memory instruction (requires Merkle proof witness)
    /// Per spec NEW-1: Placeholder verification is exploitable
    fn is_memory_instruction(opcode: u8) -> bool {
        // Memory opcodes: IADD_M=12, ISUB_M=13, IMUL_M=14, IMULH_M=15, ISMULH_M=16, IXOR_M=17
        opcode >= 12 && opcode <= 17
    }
    
    /// Check if an opcode is a control flow instruction (requires additional state)
    /// Per spec NEW-2: CBRANCH and ISTORE use placeholder verification
    fn is_control_flow_instruction(opcode: u8) -> bool {
        // CBRANCH=30, ISTORE=31
        opcode == 30 || opcode == 31
    }
    
    /// Get deferred dispute type from verification result
    /// Returns: 0=FP, 1=Memory, 2=ControlFlow, 255=NotDeferred
    /// Used for DeferredVerificationDispute event emission
    fn get_deferred_dispute_type(result: VerificationResult) -> u8 {
        match result {
            VerificationResult::FPStubRejection => 0_u8,
            VerificationResult::MemoryVerificationDeferred => 1_u8,
            VerificationResult::ControlFlowVerificationDeferred => 2_u8,
            _ => 255_u8,  // Not a deferred type
        }
    }
    
    /// Verify instruction execution proof
    /// 
    /// Returns VerificationResult indicating:
    /// - Verified: Proof is valid
    /// - Rejected: Proof is invalid (fraud detected)
    /// - FPStubRejection: FP instruction, verification not implemented
    /// - InvalidProof: Malformed proof
    /// 
    /// Per spec recommendation:
    /// FP stub rejection → Defender wins (can't prove fraud without full verification)
    fn verify_instruction_proof(proof: super::InstructionProof) -> VerificationResult {
        // Opcode constants (inline to avoid use statement issues in older Cairo)
        // CBRANCH=30, ISTORE=31, NOP=29, IADD_RS=18, ISWAP_R=9
        
        // Basic validation
        if proof.dst_idx > 7 || proof.src_idx > 7 {
            return VerificationResult::InvalidProof;
        }
        
        // Check if this is an FP instruction (opcodes 20-28)
        // NOW INTEGRATED: Actually call FP verifiers with IEEE-754 compliance
        if is_fp_instruction(proof.opcode) {
            let is_valid = verify_fp_opcode_execution(proof);
            return if is_valid {
                VerificationResult::Verified
            } else {
                VerificationResult::Rejected
            };
        }
        
        // Check if this is a memory instruction (opcodes 12-17)
        // NOW INTEGRATED: Actually call memory verifiers with Merkle proofs
        if is_memory_instruction(proof.opcode) {
            let is_valid = verify_memory_opcode_execution(proof);
            return if is_valid {
                VerificationResult::Verified
            } else {
                VerificationResult::Rejected
            };
        }
        
        // Check if this is CBRANCH (30)
        // NOW INTEGRATED: Actually call CBRANCH verifier with register tracking
        if proof.opcode == 30 {
            let is_valid = verify_cbranch_execution(proof);
            return if is_valid {
                VerificationResult::Verified
            } else {
                VerificationResult::Rejected
            };
        }
        
        // Check if this is ISTORE (31)
        // NOW INTEGRATED: Actually call ISTORE verifier with Merkle proofs
        if proof.opcode == 31 {
            let is_valid = verify_istore_execution(proof);
            return if is_valid {
                VerificationResult::Verified
            } else {
                VerificationResult::Rejected
            };
        }
        
        // Verify opcode is in valid range for integer instructions
        // Valid: 0-11 (integer register ops), 18 (IADD_RS), 29 (NOP)
        // Note: 12-17 (memory), 30 (CBRANCH), and 31 (ISTORE) now verified above
        // Note: 20-27 (FP) handled above with FPStubRejection
        let valid_opcode = proof.opcode <= 11  // 0-11: integer register ops
            || proof.opcode == 29  // NOP
            || proof.opcode == 18; // IADD_RS
        
        if !valid_opcode {
            return VerificationResult::InvalidProof;
        }
        
        // Verify instruction execution using actual verifiers from fraud_proof module
        // Each verifier checks: given pre_regs + instruction, is post_regs correct?
        // Using crate:: path since we're inside the contract module
        
        let is_valid = verify_opcode_execution(proof);

        if is_valid {
            VerificationResult::Verified
        } else {
            VerificationResult::Rejected
        }
    }
    
    /// Dispatch verification to appropriate instruction verifier
    fn verify_opcode_execution(proof: super::InstructionProof) -> bool {
        let op = proof.opcode;
        
        // Integer register instructions (0-9)
        if op == 0 {
            return crate::randomx::fraud_proof::instruction_verifiers::verify_iadd_r(
                proof.pre_regs, proof.dst_idx, proof.src_idx, proof.post_regs);
        }
        if op == 1 {
            return crate::randomx::fraud_proof::instruction_verifiers::verify_isub_r(
                proof.pre_regs, proof.dst_idx, proof.src_idx, proof.post_regs);
        }
        if op == 2 {
            return crate::randomx::fraud_proof::instruction_verifiers::verify_imul_r(
                proof.pre_regs, proof.dst_idx, proof.src_idx, proof.post_regs);
        }
        if op == 3 {
            return crate::randomx::fraud_proof::instruction_verifiers::verify_imulh_r(
                proof.pre_regs, proof.dst_idx, proof.src_idx, proof.post_regs);
        }
        if op == 4 {
            return crate::randomx::fraud_proof::instruction_verifiers::verify_ismulh_r(
                proof.pre_regs, proof.dst_idx, proof.src_idx, proof.post_regs);
        }
        // IMUL_RCP - Per spec: MUST use full version for testnet
        // Basic version only checks structure, not reciprocal correctness
        if op == 5 {
            return crate::randomx::fraud_proof::instruction_verifiers::verify_imul_rcp_full(
                proof.pre_regs, proof.dst_idx, proof.imm32, proof.post_regs);
        }
        if op == 6 {
            return crate::randomx::fraud_proof::instruction_verifiers::verify_ixor_r(
                proof.pre_regs, proof.dst_idx, proof.src_idx, proof.post_regs);
        }
        if op == 7 {
            return crate::randomx::fraud_proof::instruction_verifiers::verify_iror_r(
                proof.pre_regs, proof.dst_idx, proof.src_idx, proof.post_regs);
        }
        if op == 8 {
            return crate::randomx::fraud_proof::instruction_verifiers::verify_irol_r(
                proof.pre_regs, proof.dst_idx, proof.src_idx, proof.post_regs);
        }
        if op == 9 {
            return crate::randomx::fraud_proof::instruction_verifiers::verify_iswap_r(
                proof.pre_regs, proof.dst_idx, proof.src_idx, proof.post_regs);
        }
        // INEG_R = 11
        if op == 11 {
            return crate::randomx::fraud_proof::instruction_verifiers::verify_ineg_r(
                proof.pre_regs, proof.dst_idx, proof.post_regs);
        }
        // Memory instructions (12-17) - now handled by verify_memory_opcode_execution
        
        // IADD_RS = 18 (uses shift and imm32 for r5)
        if op == 18 {
            return crate::randomx::fraud_proof::instruction_verifiers::verify_iadd_rs(
                proof.pre_regs, proof.dst_idx, proof.src_idx,
                proof.shift, proof.imm32, proof.post_regs);
        }
        // NOP = 29
        if op == 29 {
            return crate::randomx::fraud_proof::instruction_verifiers::verify_nop(
                proof.pre_regs, proof.post_regs);
        }
        // CBRANCH (30) now handled by verify_cbranch_execution with register tracking
        // ISTORE (31) now handled by verify_istore_execution
        
        // Unknown opcode - should not reach here if opcode validation is correct
        false
    }
    
    /// Verify memory instruction execution (opcodes 12-17)
    /// Uses Merkle-verified memory reads
    fn verify_memory_opcode_execution(proof: super::InstructionProof) -> bool {
        use crate::randomx::fraud_proof::memory_verifiers::MemoryWitness;
        use crate::randomx::fraud_proof::{
            RandomXState, RegisterFile, ExecutionState, FloatRegisters, FloatRegister
        };
        
        // Build MemoryWitness from proof fields
        let witness = MemoryWitness {
            value: proof.mem_value,
            proof_len: proof.mem_proof_len,
            proof_0: proof.mem_proof_0,
            proof_1: proof.mem_proof_1,
            proof_2: proof.mem_proof_2,
            proof_3: proof.mem_proof_3,
            proof_4: proof.mem_proof_4,
            proof_5: proof.mem_proof_5,
            proof_6: proof.mem_proof_6,
            proof_7: proof.mem_proof_7,
            proof_8: proof.mem_proof_8,
            proof_9: proof.mem_proof_9,
            proof_10: proof.mem_proof_10,
            proof_11: proof.mem_proof_11,
            proof_12: proof.mem_proof_12,
            proof_13: proof.mem_proof_13,
            proof_14: proof.mem_proof_14,
        };
        
        // Helper to create zero FloatRegister
        let zero_freg = FloatRegister { low: 0, high: 0 };
        
        // Build minimal RandomXState for memory verification
        // Only scratchpad_root and int_regs are needed for memory ops
        let pre_state = RandomXState {
            registers: RegisterFile {
                int_regs: proof.pre_regs,
                float_regs: FloatRegisters {
                    f0: zero_freg, f1: zero_freg, f2: zero_freg, f3: zero_freg,
                    e0: zero_freg, e1: zero_freg, e2: zero_freg, e3: zero_freg,
                    a0: zero_freg, a1: zero_freg, a2: zero_freg, a3: zero_freg,
                },
            },
            execution: ExecutionState {
                program_counter: 0,
                iteration_counter: 0,
                program_index: 0,
                fprc: 0,
                ma: 0,
                mx: 0,
            },
            scratchpad_root: proof.scratchpad_root,
        };
        
        let op = proof.opcode;
        
        // Dispatch to appropriate memory verifier
        if op == 12 {
            return crate::randomx::fraud_proof::memory_verifiers::verify_iadd_m(
                pre_state, proof.dst_idx, proof.src_idx, proof.imm32, witness, proof.post_regs);
        }
        if op == 13 {
            return crate::randomx::fraud_proof::memory_verifiers::verify_isub_m(
                pre_state, proof.dst_idx, proof.src_idx, proof.imm32, witness, proof.post_regs);
        }
        if op == 14 {
            return crate::randomx::fraud_proof::memory_verifiers::verify_imul_m(
                pre_state, proof.dst_idx, proof.src_idx, proof.imm32, witness, proof.post_regs);
        }
        if op == 15 {
            return crate::randomx::fraud_proof::memory_verifiers::verify_imulh_m(
                pre_state, proof.dst_idx, proof.src_idx, proof.imm32, witness, proof.post_regs);
        }
        if op == 16 {
            return crate::randomx::fraud_proof::memory_verifiers::verify_ismulh_m(
                pre_state, proof.dst_idx, proof.src_idx, proof.imm32, witness, proof.post_regs);
        }
        if op == 17 {
            return crate::randomx::fraud_proof::memory_verifiers::verify_ixor_m(
                pre_state, proof.dst_idx, proof.src_idx, proof.imm32, witness, proof.post_regs);
        }
        
        // Should not reach here for memory opcodes
        false
    }
    
    /// Verify ISTORE execution (opcode 31)
    /// Uses Merkle-verified memory writes with scratchpad root update
    fn verify_istore_execution(proof: super::InstructionProof) -> bool {
        use crate::randomx::fraud_proof::memory_verifiers::StoreWitness;
        use crate::randomx::fraud_proof::{
            RandomXState, RegisterFile, ExecutionState, FloatRegisters, FloatRegister
        };
        
        // Build StoreWitness from proof fields
        let witness = StoreWitness {
            old_value: proof.store_old_value,
            new_scratchpad_root: proof.post_scratchpad_root,
            proof_len: proof.mem_proof_len,
            proof_0: proof.mem_proof_0,
            proof_1: proof.mem_proof_1,
            proof_2: proof.mem_proof_2,
            proof_3: proof.mem_proof_3,
            proof_4: proof.mem_proof_4,
            proof_5: proof.mem_proof_5,
            proof_6: proof.mem_proof_6,
            proof_7: proof.mem_proof_7,
            proof_8: proof.mem_proof_8,
            proof_9: proof.mem_proof_9,
            proof_10: proof.mem_proof_10,
            proof_11: proof.mem_proof_11,
            proof_12: proof.mem_proof_12,
            proof_13: proof.mem_proof_13,
            proof_14: proof.mem_proof_14,
        };
        
        // Helper to create zero FloatRegister
        let zero_freg = FloatRegister { low: 0, high: 0 };
        
        // Build minimal RandomXState for ISTORE verification
        let pre_state = RandomXState {
            registers: RegisterFile {
                int_regs: proof.pre_regs,
                float_regs: FloatRegisters {
                    f0: zero_freg, f1: zero_freg, f2: zero_freg, f3: zero_freg,
                    e0: zero_freg, e1: zero_freg, e2: zero_freg, e3: zero_freg,
                    a0: zero_freg, a1: zero_freg, a2: zero_freg, a3: zero_freg,
                },
            },
            execution: ExecutionState {
                program_counter: 0,
                iteration_counter: 0,
                program_index: 0,
                fprc: 0,
                ma: 0,
                mx: 0,
            },
            scratchpad_root: proof.scratchpad_root,
        };
        
        crate::randomx::fraud_proof::memory_verifiers::verify_istore(
            pre_state,
            proof.dst_idx,
            proof.src_idx,
            proof.imm32,
            proof.mod_cond,
            proof.mod_mem,
            witness,
            proof.post_scratchpad_root
        )
    }
    
    /// Verify CBRANCH execution (opcode 30)
    /// Uses register modification tracking for jump condition verification
    fn verify_cbranch_execution(proof: super::InstructionProof) -> bool {
        use crate::randomx::fraud_proof::cbranch_verifier::{
            CBranchClaim, RegisterModificationTracker
        };
        
        // Reconstruct cimm (i64) from two-part representation
        // cimm_low contains the absolute value, cimm_sign indicates negative
        let cimm: i64 = if proof.cimm_sign == 0 {
            // Positive: convert u64 to i64 directly (safe for values < 2^63)
            let val: felt252 = proof.cimm_low.into();
            val.try_into().unwrap()
        } else {
            // Negative: negate the value
            let val: felt252 = proof.cimm_low.into();
            let positive: i64 = val.try_into().unwrap();
            -positive
        };
        
        // Build CBranchClaim from proof fields
        let claim = CBranchClaim {
            dst_reg: proof.dst_idx,
            dst_value_before: get_register_value(proof.pre_regs, proof.dst_idx),
            cimm: cimm,
            mod_cond: proof.mod_cond,
            last_modified_pc: proof.last_modified_pc,
            jump_taken: proof.jump_taken,
            new_pc: proof.new_pc,
        };
        
        // Build RegisterModificationTracker from proof fields
        let tracker = RegisterModificationTracker {
            r0_last_mod: proof.r0_last_mod,
            r1_last_mod: proof.r1_last_mod,
            r2_last_mod: proof.r2_last_mod,
            r3_last_mod: proof.r3_last_mod,
            r4_last_mod: proof.r4_last_mod,
            r5_last_mod: proof.r5_last_mod,
            r6_last_mod: proof.r6_last_mod,
            r7_last_mod: proof.r7_last_mod,
        };
        
        crate::randomx::fraud_proof::cbranch_verifier::verify_cbranch(
            proof.pre_regs,
            claim,
            proof.post_regs,
            tracker,
            proof.current_pc
        )
    }
    
    /// Helper to get register value by index
    fn get_register_value(regs: super::IntegerRegisters, idx: u8) -> u64 {
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
    
    // ========================================================================
    // Floating-Point Instruction Verification (opcodes 20-28)
    // ========================================================================
    
    /// Verify floating-point instruction execution
    /// Supports FADD_R/M, FSUB_R/M, FMUL_R, FDIV_M, FSQRT_R, FSCAL_R, CFROUND
    fn verify_fp_opcode_execution(proof: super::InstructionProof) -> bool {
        let op = proof.opcode;
        
        // CFROUND (opcode 28): Set FPRC from register bits
        // This only changes FPRC state, no float register modification
        if op == 28 {
            return verify_cfround_execution(proof);
        }
        
        // FSCAL_R (opcode 27): XOR with constant mask
        // Fully verifiable without FP computation
        if op == 27 {
            return verify_fscal_r_execution(proof);
        }
        
        // For FADD_R (20), FADD_M (21), FSUB_R (22), FSUB_M (23),
        // FMUL_R (24), FDIV_M (25), FSQRT_R (26):
        // Use IEEE-754 verifiers from fraud_proof module
        
        // Get source and destination float register indices
        // F-group (f0-f3): indices 0-3 for FADD/FSUB
        // E-group (e0-e3): indices 4-7 for FMUL/FDIV/FSQRT
        // A-group (a0-a3): indices 8-11 (read-only source)
        
        if op == 20 {
            verify_fadd_r_execution(proof)  // FADD_R
        } else if op == 21 {
            verify_fadd_m_execution(proof)  // FADD_M
        } else if op == 22 {
            verify_fsub_r_execution(proof)  // FSUB_R
        } else if op == 23 {
            verify_fsub_m_execution(proof)  // FSUB_M
        } else if op == 24 {
            verify_fmul_r_execution(proof)  // FMUL_R
        } else if op == 25 {
            verify_fdiv_m_execution(proof)  // FDIV_M
        } else if op == 26 {
            verify_fsqrt_r_execution(proof) // FSQRT_R
        } else {
            false
        }
    }
    
    /// Verify CFROUND execution (opcode 28)
    /// Sets FPRC (floating-point rounding control) from src register bits
    fn verify_cfround_execution(proof: super::InstructionProof) -> bool {
        // CFROUND extracts 2 bits from src register, rotated by imm32
        // Per RandomX spec: fprc = (src >> (imm32 & 63)) & 3
        let src_val = get_register_value(proof.pre_regs, proof.src_idx);
        let rotation: u32 = proof.imm32 & 63;
        
        // Rotate right by rotation amount
        let rotated: u64 = if rotation == 0 {
            src_val
        } else {
            let rot_u64: u64 = rotation.into();
            (src_val / pow2_u64(rot_u64)) | (src_val * pow2_u64(64 - rot_u64))
        };
        
        // Extract 2 LSBs
        let expected_fprc: u8 = (rotated & 3).try_into().unwrap();
        
        // Verify FPRC in proof matches expected
        proof.fprc == expected_fprc
            // CFROUND does not modify any registers
            && proof.pre_regs == proof.post_regs
            && proof.pre_float_regs == proof.post_float_regs
    }
    
    /// Power of 2 helper for u64
    fn pow2_u64(exp: u64) -> u64 {
        if exp >= 64 { return 0; }
        let mut result: u64 = 1;
        let mut i: u64 = 0;
        loop {
            if i >= exp { break; }
            result = result * 2;
            i += 1;
        };
        result
    }
    
    /// Verify FSCAL_R execution (opcode 27)
    /// XORs F-group register with constant mask 0x80F0000000000000
    fn verify_fscal_r_execution(proof: super::InstructionProof) -> bool {
        // FSCAL_R operates on F-group (f0-f3, indices 0-3)
        if proof.dst_idx >= 4 {
            return false;
        }
        
        const FSCAL_MASK: u64 = 0x80F0000000000000;
        
        // Get pre and post values for destination register
        let (pre_lo, pre_hi) = get_float_register(proof.pre_float_regs, proof.dst_idx);
        let (post_lo, post_hi) = get_float_register(proof.post_float_regs, proof.dst_idx);
        
        // Verify XOR operation on both lanes
        let expected_lo = pre_lo ^ FSCAL_MASK;
        let expected_hi = pre_hi ^ FSCAL_MASK;
        
        post_lo == expected_lo && post_hi == expected_hi
            // Other float registers unchanged
            && verify_other_float_regs_unchanged(
                proof.pre_float_regs, proof.post_float_regs, proof.dst_idx)
            // Integer registers unchanged
            && proof.pre_regs == proof.post_regs
    }
    
    /// Build FPWitness for lane 1 (lo) from proof fields
    fn build_fp_witness_lo(proof: super::InstructionProof, is_sub: u8) -> crate::randomx::fraud_proof::ieee754::FPWitness {
        crate::randomx::fraud_proof::ieee754::FPWitness {
            extended_mantissa_hi: proof.fp_witness_mantissa_hi,
            extended_mantissa_lo: proof.fp_witness_mantissa_lo,
            rounding_adjustment: proof.fp_witness_rounding_adj.try_into().unwrap(),
            guard_round_sticky: proof.fp_witness_grs,
            result_exponent: proof.fp_witness_exponent,
            normalization_shift: proof.fp_witness_norm_shift,
            alignment_shift: proof.fp_witness_shift,
            sign_a: 0,  // Derived from operands
            sign_b: 0,  // Derived from operands
            sign_result: proof.fp_witness_result_sign,
            ftz_daz_active: 1,  // RandomX always uses FTZ/DAZ
            fprc_at_execution: proof.fprc,
            is_sub: is_sub,
        }
    }
    
    /// Build FPWitness for lane 2 (hi) from proof fields
    fn build_fp_witness_hi(proof: super::InstructionProof, is_sub: u8) -> crate::randomx::fraud_proof::ieee754::FPWitness {
        crate::randomx::fraud_proof::ieee754::FPWitness {
            extended_mantissa_hi: proof.fp_witness2_mantissa_hi,
            extended_mantissa_lo: proof.fp_witness2_mantissa_lo,
            rounding_adjustment: proof.fp_witness2_rounding_adj.try_into().unwrap(),
            guard_round_sticky: proof.fp_witness2_grs,
            result_exponent: proof.fp_witness2_exponent,
            normalization_shift: proof.fp_witness2_norm_shift,
            alignment_shift: proof.fp_witness2_shift,
            sign_a: 0,
            sign_b: 0,
            sign_result: proof.fp_witness2_result_sign,
            ftz_daz_active: 1,
            fprc_at_execution: proof.fprc,
            is_sub: is_sub,
        }
    }
    
    /// Verify FADD_R execution (opcode 20) with witness-based verification
    /// dst_lo/hi = dst_lo/hi + a_lo/hi (F-group + A-group)
    fn verify_fadd_r_execution(proof: super::InstructionProof) -> bool {
        // FADD_R: dst is F-group (0-3), src is A-group (8-11)
        if proof.dst_idx >= 4 {
            return false;
        }
        
        let (pre_dst_lo, pre_dst_hi) = get_float_register(proof.pre_float_regs, proof.dst_idx);
        let (post_dst_lo, post_dst_hi) = get_float_register(proof.post_float_regs, proof.dst_idx);
        
        // A-group source: offset by 8 in indexing, but stored as a0-a3 (indices 8-11)
        let src_idx = proof.src_idx;
        let (src_lo, src_hi) = get_float_register(proof.pre_float_regs, src_idx + 8);
        
        // Build witnesses for both lanes
        let witness_lo = build_fp_witness_lo(proof, 0);  // is_sub = 0 for FADD
        let witness_hi = build_fp_witness_hi(proof, 0);
        
        // Verify both lanes using witness-based IEEE-754 verifier
        let lo_valid = crate::randomx::fraud_proof::ieee754::verify_fadd_with_witness(
            pre_dst_lo, src_lo, post_dst_lo, proof.fprc, witness_lo);
        let hi_valid = crate::randomx::fraud_proof::ieee754::verify_fadd_with_witness(
            pre_dst_hi, src_hi, post_dst_hi, proof.fprc, witness_hi);
        
        lo_valid && hi_valid
            && verify_other_float_regs_unchanged(
                proof.pre_float_regs, proof.post_float_regs, proof.dst_idx)
            && proof.pre_regs == proof.post_regs
    }
    
    /// Verify FADD_M execution (opcode 21) with witness-based verification
    /// dst_lo/hi = dst_lo/hi + convert(mem) (F-group + memory)
    fn verify_fadd_m_execution(proof: super::InstructionProof) -> bool {
        // FADD_M: dst is F-group (0-3)
        if proof.dst_idx >= 4 {
            return false;
        }
        
        let (pre_dst_lo, pre_dst_hi) = get_float_register(proof.pre_float_regs, proof.dst_idx);
        let (post_dst_lo, post_dst_hi) = get_float_register(proof.post_float_regs, proof.dst_idx);
        
        // Convert memory value to F-group operand (signed int32 halves to double)
        let (src_lo, src_hi) = crate::randomx::fraud_proof::ieee754::convert_f_group_operand(
            proof.mem_value);
        
        // Build witnesses for both lanes
        let witness_lo = build_fp_witness_lo(proof, 0);
        let witness_hi = build_fp_witness_hi(proof, 0);
        
        // Verify both lanes with witness
        let lo_valid = crate::randomx::fraud_proof::ieee754::verify_fadd_with_witness(
            pre_dst_lo, src_lo, post_dst_lo, proof.fprc, witness_lo);
        let hi_valid = crate::randomx::fraud_proof::ieee754::verify_fadd_with_witness(
            pre_dst_hi, src_hi, post_dst_hi, proof.fprc, witness_hi);
        
        lo_valid && hi_valid
            && verify_other_float_regs_unchanged(
                proof.pre_float_regs, proof.post_float_regs, proof.dst_idx)
            && proof.pre_regs == proof.post_regs
    }
    
    /// Verify FSUB_R execution (opcode 22) with witness-based verification
    fn verify_fsub_r_execution(proof: super::InstructionProof) -> bool {
        if proof.dst_idx >= 4 {
            return false;
        }
        
        let (pre_dst_lo, pre_dst_hi) = get_float_register(proof.pre_float_regs, proof.dst_idx);
        let (post_dst_lo, post_dst_hi) = get_float_register(proof.post_float_regs, proof.dst_idx);
        let src_idx = proof.src_idx;
        let (src_lo, src_hi) = get_float_register(proof.pre_float_regs, src_idx + 8);
        
        // Build witnesses for subtraction (is_sub = 1)
        let witness_lo = build_fp_witness_lo(proof, 1);
        let witness_hi = build_fp_witness_hi(proof, 1);
        
        // FSUB uses FADD verifier with negated src (handled internally by verify_fsub_with_witness)
        // But we'll use the same witness structure with is_sub flag
        let lo_valid = crate::randomx::fraud_proof::ieee754::verify_fadd_with_witness(
            pre_dst_lo, src_lo ^ 0x8000000000000000, post_dst_lo, proof.fprc, witness_lo);
        let hi_valid = crate::randomx::fraud_proof::ieee754::verify_fadd_with_witness(
            pre_dst_hi, src_hi ^ 0x8000000000000000, post_dst_hi, proof.fprc, witness_hi);
        
        lo_valid && hi_valid
            && verify_other_float_regs_unchanged(
                proof.pre_float_regs, proof.post_float_regs, proof.dst_idx)
            && proof.pre_regs == proof.post_regs
    }
    
    /// Verify FSUB_M execution (opcode 23) with witness-based verification
    fn verify_fsub_m_execution(proof: super::InstructionProof) -> bool {
        if proof.dst_idx >= 4 {
            return false;
        }
        
        let (pre_dst_lo, pre_dst_hi) = get_float_register(proof.pre_float_regs, proof.dst_idx);
        let (post_dst_lo, post_dst_hi) = get_float_register(proof.post_float_regs, proof.dst_idx);
        let (src_lo, src_hi) = crate::randomx::fraud_proof::ieee754::convert_f_group_operand(
            proof.mem_value);
        
        // Build witnesses for subtraction
        let witness_lo = build_fp_witness_lo(proof, 1);
        let witness_hi = build_fp_witness_hi(proof, 1);
        
        // Negate sources for subtraction
        let lo_valid = crate::randomx::fraud_proof::ieee754::verify_fadd_with_witness(
            pre_dst_lo, src_lo ^ 0x8000000000000000, post_dst_lo, proof.fprc, witness_lo);
        let hi_valid = crate::randomx::fraud_proof::ieee754::verify_fadd_with_witness(
            pre_dst_hi, src_hi ^ 0x8000000000000000, post_dst_hi, proof.fprc, witness_hi);
        
        lo_valid && hi_valid
            && verify_other_float_regs_unchanged(
                proof.pre_float_regs, proof.post_float_regs, proof.dst_idx)
            && proof.pre_regs == proof.post_regs
    }
    
    /// Verify FMUL_R execution (opcode 24) with witness-based verification
    /// E-group multiplication: dst = dst * src
    fn verify_fmul_r_execution(proof: super::InstructionProof) -> bool {
        // FMUL_R: dst is E-group (indices 4-7 in our scheme, e0-e3)
        if proof.dst_idx < 4 || proof.dst_idx >= 8 {
            return false;
        }
        
        let (pre_dst_lo, pre_dst_hi) = get_float_register(proof.pre_float_regs, proof.dst_idx);
        let (post_dst_lo, post_dst_hi) = get_float_register(proof.post_float_regs, proof.dst_idx);
        // A-group source for FMUL_R
        let src_idx = proof.src_idx;
        let (src_lo, src_hi) = get_float_register(proof.pre_float_regs, src_idx + 8);
        
        // Build witnesses for multiplication
        let witness_lo = build_fp_witness_lo(proof, 0);
        let witness_hi = build_fp_witness_hi(proof, 0);
        
        let lo_valid = crate::randomx::fraud_proof::ieee754::verify_fmul_with_witness(
            pre_dst_lo, src_lo, post_dst_lo, proof.fprc, witness_lo);
        let hi_valid = crate::randomx::fraud_proof::ieee754::verify_fmul_with_witness(
            pre_dst_hi, src_hi, post_dst_hi, proof.fprc, witness_hi);
        
        lo_valid && hi_valid
            && verify_other_float_regs_unchanged(
                proof.pre_float_regs, proof.post_float_regs, proof.dst_idx)
            && proof.pre_regs == proof.post_regs
    }
    
    /// Verify FDIV_M execution (opcode 25) with witness-based verification
    /// E-group division with memory source and E-mask
    /// Includes E-mask source entropy validation
    fn verify_fdiv_m_execution(proof: super::InstructionProof) -> bool {
        if proof.dst_idx < 4 || proof.dst_idx >= 8 {
            return false;
        }
        
        // E-MASK SOURCE VALIDATION:
        // Verify that proof.e_mask matches compute_e_mask(proof.e_mask_entropy)
        // This prevents attackers from providing arbitrary e_mask values
        let expected_e_mask = crate::randomx::fraud_proof::ieee754::compute_e_mask(
            proof.e_mask_entropy);
        if proof.e_mask != expected_e_mask {
            return false;  // E-mask doesn't match entropy source
        }
        
        let (pre_dst_lo, pre_dst_hi) = get_float_register(proof.pre_float_regs, proof.dst_idx);
        let (post_dst_lo, post_dst_hi) = get_float_register(proof.post_float_regs, proof.dst_idx);
        
        // Build witnesses for division
        let witness_lo = build_fp_witness_lo(proof, 0);
        let witness_hi = build_fp_witness_hi(proof, 0);
        
        // Apply E-mask to memory value to get divisor
        let divisor = crate::randomx::fraud_proof::ieee754::apply_e_group_mask(
            proof.mem_value, proof.e_mask);
        
        // For FDIV_M, the divisor comes from memory with E-mask applied
        let lo_valid = crate::randomx::fraud_proof::ieee754::verify_fdiv_with_witness(
            pre_dst_lo, divisor, post_dst_lo, proof.fprc, witness_lo);
        let hi_valid = crate::randomx::fraud_proof::ieee754::verify_fdiv_with_witness(
            pre_dst_hi, divisor, post_dst_hi, proof.fprc, witness_hi);
        
        lo_valid && hi_valid
            && verify_other_float_regs_unchanged(
                proof.pre_float_regs, proof.post_float_regs, proof.dst_idx)
            && proof.pre_regs == proof.post_regs
    }
    
    /// Verify FSQRT_R execution (opcode 26) with witness-based verification
    /// E-group square root
    fn verify_fsqrt_r_execution(proof: super::InstructionProof) -> bool {
        if proof.dst_idx < 4 || proof.dst_idx >= 8 {
            return false;
        }
        
        let (pre_dst_lo, pre_dst_hi) = get_float_register(proof.pre_float_regs, proof.dst_idx);
        let (post_dst_lo, post_dst_hi) = get_float_register(proof.post_float_regs, proof.dst_idx);
        
        // Build witnesses for square root
        let witness_lo = build_fp_witness_lo(proof, 0);
        let witness_hi = build_fp_witness_hi(proof, 0);
        
        let lo_valid = crate::randomx::fraud_proof::ieee754::verify_fsqrt_with_witness(
            pre_dst_lo, post_dst_lo, proof.fprc, witness_lo);
        let hi_valid = crate::randomx::fraud_proof::ieee754::verify_fsqrt_with_witness(
            pre_dst_hi, post_dst_hi, proof.fprc, witness_hi);
        
        lo_valid && hi_valid
            && verify_other_float_regs_unchanged(
                proof.pre_float_regs, proof.post_float_regs, proof.dst_idx)
            && proof.pre_regs == proof.post_regs
    }
    
    /// Get float register value by index (0-11)
    /// 0-3: F-group (f0-f3), 4-7: E-group (e0-e3), 8-11: A-group (a0-a3)
    fn get_float_register(regs: super::FloatRegisters, idx: u8) -> (u64, u64) {
        match idx {
            0 => (regs.f0.low, regs.f0.high),
            1 => (regs.f1.low, regs.f1.high),
            2 => (regs.f2.low, regs.f2.high),
            3 => (regs.f3.low, regs.f3.high),
            4 => (regs.e0.low, regs.e0.high),
            5 => (regs.e1.low, regs.e1.high),
            6 => (regs.e2.low, regs.e2.high),
            7 => (regs.e3.low, regs.e3.high),
            8 => (regs.a0.low, regs.a0.high),
            9 => (regs.a1.low, regs.a1.high),
            10 => (regs.a2.low, regs.a2.high),
            11 => (regs.a3.low, regs.a3.high),
            _ => (0, 0),
        }
    }
    
    /// Verify other float registers unchanged (except dst_idx)
    fn verify_other_float_regs_unchanged(
        pre: super::FloatRegisters,
        post: super::FloatRegisters,
        dst_idx: u8
    ) -> bool {
        // Check all registers except dst_idx
        (dst_idx == 0 || pre.f0 == post.f0) &&
        (dst_idx == 1 || pre.f1 == post.f1) &&
        (dst_idx == 2 || pre.f2 == post.f2) &&
        (dst_idx == 3 || pre.f3 == post.f3) &&
        (dst_idx == 4 || pre.e0 == post.e0) &&
        (dst_idx == 5 || pre.e1 == post.e1) &&
        (dst_idx == 6 || pre.e2 == post.e2) &&
        (dst_idx == 7 || pre.e3 == post.e3) &&
        // A-group is always read-only
        pre.a0 == post.a0 &&
        pre.a1 == post.a1 &&
        pre.a2 == post.a2 &&
        pre.a3 == post.a3
    }
    
    /// Resolve dispute based on verification result
    /// 
    /// Per spec recommendation:
    /// - Verified: Prover (whoever submitted) wins
    /// - Rejected: Prover loses (fraud detected or wrong execution)
    /// - FPStubRejection: Defender wins (can't prove fraud without FP verification)
    /// - InvalidProof: Prover loses
    fn resolve_dispute(
        result: VerificationResult,
        is_challenger: bool,
        challenger: ContractAddress,
        defender: ContractAddress
    ) -> ContractAddress {
        match result {
            VerificationResult::Verified => {
                // Prover submitted valid proof, they win
                if is_challenger { challenger } else { defender }
            },
            VerificationResult::Rejected => {
                // Proof rejected, prover loses
                if is_challenger { defender } else { challenger }
            },
            VerificationResult::FPStubRejection => {
                // FP instruction, can't verify → Defender wins
                // Rationale: "If challenger cannot prove fraud, they haven't proven anything"
                defender
            },
            VerificationResult::MemoryVerificationDeferred => {
                // Memory instruction, can't verify without Merkle witness → Defender wins
                // Per spec NEW-1: Safer than placeholder that only checks hash difference
                defender
            },
            VerificationResult::ControlFlowVerificationDeferred => {
                // CBRANCH/ISTORE, can't verify without full state → Defender wins
                // Per spec NEW-2: Safer than placeholder that only checks hash difference
                defender
            },
            VerificationResult::InvalidProof => {
                // Malformed proof, prover loses
                if is_challenger { defender } else { challenger }
            },
        }
    }
}
