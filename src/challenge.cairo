/// MoneroVM Challenge Contract
/// 
/// Handles fraud proof disputes for RandomX verification.
/// Inspired by BitVM and Arbitrum's optimistic verification patterns.

use starknet::ContractAddress;

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
    
    // CRITICAL: INEG_R = 11 (Per auditor, frequency 2/256)
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
    
    // FP instructions (20-31)
    pub const FADD_R: u8 = 20;
    pub const FADD_M: u8 = 21;
    pub const FSUB_R: u8 = 22;
    pub const FSUB_M: u8 = 23;
    pub const FMUL_R: u8 = 24;
    pub const FDIV_M: u8 = 25;
    pub const FSQRT_R: u8 = 26;
    pub const FSCAL_R: u8 = 27;
    
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
    /// Immediate value (for memory instructions)
    pub imm32: u32,
    /// Pre-execution state hash
    pub pre_state_hash: felt252,
    /// Post-execution state hash (claimed)
    pub post_state_hash: felt252,
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
    }
    
    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ChallengeOpened: ChallengeOpened,
        ChallengeDefended: ChallengeDefended,
        BisectionMove: BisectionMove,
        ChallengeResolved: ChallengeResolved,
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
            
            // Increment challenge counter
            let challenge_id = self.challenge_count.read() + 1;
            self.challenge_count.write(challenge_id);
            
            // Create initial bisection state (full program range)
            let bisection = BisectionState {
                left: 0,
                right: 256,  // 256 instructions per program
                round: 0,
                challenger_turn: false,  // Defender responds first
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
            
            // Verify it's caller's turn
            let expected_caller = if challenge.bisection.challenger_turn {
                challenge.challenger
            } else {
                challenge.defender
            };
            assert(caller == expected_caller, 'Not your turn');
            
            // Verify Merkle proof for midpoint state
            let midpoint = (challenge.bisection.left + challenge.bisection.right) / 2;
            let trace_root = if challenge.bisection.challenger_turn {
                challenge.challenger_trace_root
            } else {
                challenge.defender_trace_root
            };
            
            // PRT security: verify claimed state is consistent with trace root
            assert(
                verify_merkle_proof(trace_root, midpoint, midpoint_state_hash, merkle_proof),
                'Invalid Merkle proof'
            );
            
            // Update bisection bounds based on disagreement
            // (Simplified: in practice, both parties submit and we find disagreement)
            let new_round = challenge.bisection.round + 1;
            
            // Check if we've reached single instruction
            if new_round >= constants::MVP_BISECTION_ROUNDS {
                challenge.status = ChallengeStatus::AwaitingProof;
            } else {
                // Update bounds (simplified: bisect left half)
                challenge.bisection.right = midpoint;
                challenge.bisection.round = new_round;
                challenge.bisection.challenger_turn = !challenge.bisection.challenger_turn;
            }
            
            challenge.last_action_at = timestamp;
            
            // Emit event
            self.emit(BisectionMove {
                challenge_id,
                round: new_round,
                new_left: challenge.bisection.left,
                new_right: challenge.bisection.right,
            });
            
            // Store updated challenge
            self.challenges.write(challenge_id, challenge);
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
            // - InvalidProof: Prover loses
            let verification_result = verify_instruction_proof(proof);
            
            // Determine winner based on verification result
            // Per auditor: FP stub rejection → Defender wins
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
    /// Per auditor recommendation: FP stub rejection should favor defender
    #[derive(Drop, Copy, PartialEq)]
    enum VerificationResult {
        /// Proof verified successfully - prover wins
        Verified,
        /// Proof rejected (fraud proven) - challenger wins if they submitted proof
        Rejected,
        /// FP instruction but verification not implemented - defender wins
        /// Rationale: Can't prove fraud without full verification
        FPStubRejection,
        /// Invalid proof structure
        InvalidProof,
    }
    
    /// Check if an opcode is a floating-point instruction
    fn is_fp_instruction(opcode: u8) -> bool {
        // FP opcodes: FADD_R=20, FADD_M=21, FSUB_R=22, FSUB_M=23, FMUL_R=24, FDIV_M=25, FSQRT_R=26, FSCAL_R=27
        opcode >= 20 && opcode <= 27
    }
    
    /// Verify instruction execution proof
    /// 
    /// Returns VerificationResult indicating:
    /// - Verified: Proof is valid
    /// - Rejected: Proof is invalid (fraud detected)
    /// - FPStubRejection: FP instruction, verification not implemented
    /// - InvalidProof: Malformed proof
    /// 
    /// Per auditor recommendation:
    /// FP stub rejection → Defender wins (can't prove fraud without full verification)
    fn verify_instruction_proof(proof: super::InstructionProof) -> VerificationResult {
        // Opcode constants (inline to avoid use statement issues in older Cairo)
        // CBRANCH=30, ISTORE=31, NOP=29, IADD_RS=18, ISWAP_R=9
        
        // Basic validation
        if proof.dst_idx > 7 || proof.src_idx > 7 {
            return VerificationResult::InvalidProof;
        }
        
        // Check if this is an FP instruction (opcodes 20-27)
        // Per auditor: "FP stubs rejecting = incomplete verification, not fraud detection"
        if is_fp_instruction(proof.opcode) {
            return VerificationResult::FPStubRejection;
        }
        
        // Verify opcode is in valid range for integer instructions
        // Valid: 0-14 (integer), 18 (IADD_RS), 29 (NOP), 30 (CBRANCH), 31 (ISTORE)
        let valid_opcode = proof.opcode <= 14 
            || proof.opcode == 30  // CBRANCH
            || proof.opcode == 31  // ISTORE
            || proof.opcode == 29  // NOP
            || proof.opcode == 18; // IADD_RS
        
        if !valid_opcode {
            return VerificationResult::InvalidProof;
        }
        
        // Pre-state and post-state hashes must be different
        // (unless it's a no-op like ISWAP_R with same src/dst or NOP)
        if proof.opcode == 9 && proof.dst_idx == proof.src_idx {  // ISWAP_R
            // No-op case: states should be identical
            if proof.pre_state_hash == proof.post_state_hash {
                return VerificationResult::Verified;
            } else {
                return VerificationResult::Rejected;
            }
        }
        
        if proof.opcode == 29 {  // NOP
            // NOP: states should be identical
            if proof.pre_state_hash == proof.post_state_hash {
                return VerificationResult::Verified;
            } else {
                return VerificationResult::Rejected;
            }
        }
        
        // For all other instructions, states must be different
        // (in a full implementation, we'd reconstruct and verify the actual computation)
        if proof.pre_state_hash != proof.post_state_hash {
            VerificationResult::Verified
        } else {
            VerificationResult::Rejected
        }
    }
    
    /// Resolve dispute based on verification result
    /// 
    /// Per auditor recommendation:
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
            VerificationResult::InvalidProof => {
                // Malformed proof, prover loses
                if is_challenger { defender } else { challenger }
            },
        }
    }
}
