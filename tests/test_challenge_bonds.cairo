//! Bond Enforcement Security Tests (Auditor-Grade)
//!
//! TDD-style tests for ERC20 bond enforcement in the Challenge contract.
//! Covers edge cases an auditor would require:
//! - Bond disabled vs enabled paths
//! - Insufficient allowance/balance rejection
//! - Winner receives correct bond amounts on resolution
//! - Timeout paths (defender never defended → only challenger_bond)
//! - Contract accounting (bonds held during challenge)

use core::traits::TryInto;
use core::integer::u256;
use monero_vm::challenge::{
    ChallengeContract, IChallengeContractDispatcher, IChallengeContractDispatcherTrait,
    ChallengeStatus, IntegerRegisters, InstructionProof, FloatRegister, FloatRegisters,
};
use starknet::ContractAddress;
use snforge_std_deprecated::{
    declare, ContractClassTrait, DeclareResultTrait,
    start_cheat_caller_address, stop_cheat_caller_address,
    start_cheat_block_timestamp, stop_cheat_block_timestamp
};

// ============================================================================
// Mock ERC20 (OpenZeppelin-compatible interface for bond tests)
// ============================================================================

#[starknet::interface]
trait IMockERC20<TContractState> {
    fn balance_of(self: @TContractState, account: ContractAddress) -> u256;
    fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
    fn transfer_from(
        ref self: TContractState,
        sender: ContractAddress,
        recipient: ContractAddress,
        amount: u256,
    ) -> bool;
    fn mint(ref self: TContractState, to: ContractAddress, amount: u256);
    fn approve(ref self: TContractState, spender: ContractAddress, amount: u256) -> bool;
}

#[starknet::contract]
mod MockERC20 {
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    use core::integer::u256;

    #[storage]
    struct Storage {
        balances: Map<ContractAddress, u256>,
        allowances: Map<(ContractAddress, ContractAddress), u256>,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl MockERC20Impl of super::IMockERC20<ContractState> {
        fn balance_of(self: @ContractState, account: ContractAddress) -> u256 {
            self.balances.read(account)
        }

        fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
            let sender = get_caller_address();
            let sender_balance = self.balances.read(sender);
            assert(sender_balance >= amount, 'Insufficient balance');
            self.balances.write(sender, sender_balance - amount);
            self.balances.write(recipient, self.balances.read(recipient) + amount);
            true
        }

        fn transfer_from(
            ref self: ContractState,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256,
        ) -> bool {
            let caller = get_caller_address();
            let allowance = self.allowances.read((sender, caller));
            assert(allowance >= amount, 'Insufficient allowance');
            let sender_balance = self.balances.read(sender);
            assert(sender_balance >= amount, 'Insufficient balance');
            self.allowances.write((sender, caller), allowance - amount);
            self.balances.write(sender, sender_balance - amount);
            self.balances.write(recipient, self.balances.read(recipient) + amount);
            true
        }

        fn mint(ref self: ContractState, to: ContractAddress, amount: u256) {
            self.balances.write(to, self.balances.read(to) + amount);
        }

        fn approve(ref self: ContractState, spender: ContractAddress, amount: u256) -> bool {
            let owner = get_caller_address();
            self.allowances.write((owner, spender), amount);
            true
        }
    }
}

// ============================================================================
// Test Helpers
// ============================================================================

fn challenger() -> ContractAddress {
    0x100.try_into().unwrap()
}

fn defender() -> ContractAddress {
    0x200.try_into().unwrap()
}

fn zero_regs() -> IntegerRegisters {
    IntegerRegisters { r0: 0, r1: 0, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0 }
}

fn zero_float_reg() -> FloatRegister {
    FloatRegister { low: 0, high: 0 }
}

fn zero_float_regs() -> FloatRegisters {
    FloatRegisters {
        f0: zero_float_reg(), f1: zero_float_reg(), f2: zero_float_reg(), f3: zero_float_reg(),
        e0: zero_float_reg(), e1: zero_float_reg(), e2: zero_float_reg(), e3: zero_float_reg(),
        a0: zero_float_reg(), a1: zero_float_reg(), a2: zero_float_reg(), a3: zero_float_reg(),
    }
}

fn default_proof(
    opcode: u8,
    dst_idx: u8,
    src_idx: u8,
    imm32: u32,
    shift: u8,
    pre_regs: IntegerRegisters,
    post_regs: IntegerRegisters,
) -> InstructionProof {
    InstructionProof {
        opcode,
        dst_idx,
        src_idx,
        imm32,
        shift,
        pre_state_hash: 0x1,
        post_state_hash: 0x2,
        pre_regs,
        post_regs,
        scratchpad_root: 0,
        mem_value: 0,
        mem_proof_len: 0,
        mem_proof_0: 0, mem_proof_1: 0, mem_proof_2: 0, mem_proof_3: 0,
        mem_proof_4: 0, mem_proof_5: 0, mem_proof_6: 0, mem_proof_7: 0,
        mem_proof_8: 0, mem_proof_9: 0, mem_proof_10: 0, mem_proof_11: 0,
        mem_proof_12: 0, mem_proof_13: 0, mem_proof_14: 0,
        mod_cond: 0,
        mod_mem: 0,
        store_old_value: 0,
        post_scratchpad_root: 0,
        cimm_low: 0,
        cimm_sign: 0,
        last_modified_pc: 0xFFFFFFFF,
        jump_taken: false,
        new_pc: 0,
        current_pc: 0,
        r0_last_mod: 0xFFFFFFFF,
        r1_last_mod: 0xFFFFFFFF,
        r2_last_mod: 0xFFFFFFFF,
        r3_last_mod: 0xFFFFFFFF,
        r4_last_mod: 0xFFFFFFFF,
        r5_last_mod: 0xFFFFFFFF,
        r6_last_mod: 0xFFFFFFFF,
        r7_last_mod: 0xFFFFFFFF,
        pre_float_regs: zero_float_regs(),
        post_float_regs: zero_float_regs(),
        fprc: 0,
        e_mask: 0,
        fp_witness_mantissa_hi: 0,
        fp_witness_mantissa_lo: 0,
        fp_witness_rounding_adj: 0,
        fp_witness_grs: 0,
        fp_witness_shift: 0,
        fp_witness_result_sign: 0,
        fp_witness_exponent: 0,
        fp_witness_norm_shift: 0,
        fp_witness_is_sub: 0,
        fp_witness2_mantissa_hi: 0,
        fp_witness2_mantissa_lo: 0,
        fp_witness2_rounding_adj: 0,
        fp_witness2_grs: 0,
        fp_witness2_shift: 0,
        fp_witness2_result_sign: 0,
        fp_witness2_exponent: 0,
        fp_witness2_norm_shift: 0,
        fp_witness2_is_sub: 0,
        e_mask_entropy: 0,
    }
}

use core::poseidon::poseidon_hash_span;
use core::array::ArrayTrait;

fn build_merkle_root(leaves: Span<felt252>) -> felt252 {
    let mut current_level: Array<felt252> = array![];
    let mut i: u32 = 0;
    loop {
        if i >= leaves.len() { break; }
        current_level.append(*leaves.at(i));
        i += 1;
    };
    loop {
        if current_level.len() <= 1 { break; }
        let mut next_level: Array<felt252> = array![];
        let mut j: u32 = 0;
        loop {
            if j >= current_level.len() { break; }
            let left = *current_level.at(j);
            let right = if j + 1 < current_level.len() {
                *current_level.at(j + 1)
            } else { left };
            next_level.append(poseidon_hash_span(array![left, right].span()));
            j += 2;
        };
        current_level = next_level;
    };
    *current_level.at(0)
}

fn generate_merkle_proof(leaves: Span<felt252>, index: u32) -> Array<felt252> {
    let mut proof: Array<felt252> = array![];
    let mut current_level: Array<felt252> = array![];
    let mut i: u32 = 0;
    loop {
        if i >= leaves.len() { break; }
        current_level.append(*leaves.at(i));
        i += 1;
    };
    let mut current_index = index;
    loop {
        if current_level.len() <= 1 { break; }
        let mut next_level: Array<felt252> = array![];
        let mut j: u32 = 0;
        loop {
            if j >= current_level.len() { break; }
            let left = *current_level.at(j);
            let right = if j + 1 < current_level.len() {
                *current_level.at(j + 1)
            } else { left };
            let sibling = if j == current_index { right } else { left };
            if j == current_index || j + 1 == current_index {
                proof.append(sibling);
            }
            next_level.append(poseidon_hash_span(array![left, right].span()));
            j += 2;
        };
        current_level = next_level;
        current_index = current_index / 2;
    };
    proof
}

pub const CHALLENGER_BOND: u256 = 100000000000000000;
pub const DEFENDER_BOND: u256 = 200000000000000000;
pub const BOTH_BONDS: u256 = 300000000000000000;

/// Deploy challenge with bonds disabled (bond_token=0)
fn deploy_challenge_no_bonds() -> IChallengeContractDispatcher {
    let contract = declare("ChallengeContract").unwrap().contract_class();
    let owner: ContractAddress = 0x1.try_into().unwrap();
    let bond_token: ContractAddress = 0.try_into().unwrap();
    let (contract_address, _) = contract.deploy(@array![owner.into(), bond_token.into()]).unwrap();
    IChallengeContractDispatcher { contract_address }
}

/// Deploy challenge with bonds enabled; returns (challenge, token) dispatchers
fn deploy_challenge_with_bonds() -> (IChallengeContractDispatcher, IMockERC20Dispatcher) {
    let token_class = declare("MockERC20").unwrap().contract_class();
    let (token_address, _) = token_class.deploy(@array![]).unwrap();
    let token = IMockERC20Dispatcher { contract_address: token_address };

    let mint_amount = u256 { low: 1000000000000000000, high: 0 };
    token.mint(challenger(), mint_amount);
    token.mint(defender(), mint_amount);

    let contract = declare("ChallengeContract").unwrap().contract_class();
    let owner: ContractAddress = 0x1.try_into().unwrap();
    let (challenge_address, _) = contract.deploy(@array![owner.into(), token_address.into()]).unwrap();
    let challenge = IChallengeContractDispatcher { contract_address: challenge_address };

    let approve_amount = u256 { low: 0xFFFFFFFFFFFFFFFF, high: 0xFFFFFFFFFFFFFFFF };
    start_cheat_caller_address(token.contract_address, challenger());
    token.approve(challenge_address, approve_amount);
    stop_cheat_caller_address(token.contract_address);

    start_cheat_caller_address(token.contract_address, defender());
    token.approve(challenge_address, approve_amount);
    stop_cheat_caller_address(token.contract_address);

    (challenge, token)
}

// ============================================================================
// AUDITOR-GRADE BOND TESTS
// ============================================================================

/// Bond disabled: open_challenge succeeds without any token setup
#[test]
fn test_bond_disabled_open_succeeds_without_tokens() {
    let dispatcher = deploy_challenge_no_bonds();
    start_cheat_caller_address(dispatcher.contract_address, challenger());
    let challenge_id = dispatcher.open_challenge(defender(), 0x1, 0x2, 0x3, 0x4);
    stop_cheat_caller_address(dispatcher.contract_address);
    assert(challenge_id == 1, 'Challenge should open');
}

/// Bond enabled: open_challenge fails without approval
#[test]
#[should_panic(expected: ('Insufficient allowance',))]
fn test_bond_enabled_open_fails_without_approval() {
    let token_class = declare("MockERC20").unwrap().contract_class();
    let (token_address, _) = token_class.deploy(@array![]).unwrap();
    let token = IMockERC20Dispatcher { contract_address: token_address };
    token.mint(challenger(), u256 { low: 1000000000000000000, high: 0 });
    token.mint(defender(), u256 { low: 1000000000000000000, high: 0 });
    let contract = declare("ChallengeContract").unwrap().contract_class();
    let owner: ContractAddress = 0x1.try_into().unwrap();
    let (challenge_address, _) = contract.deploy(@array![owner.into(), token_address.into()]).unwrap();
    let challenge = IChallengeContractDispatcher { contract_address: challenge_address };
    start_cheat_caller_address(challenge.contract_address, challenger());
    challenge.open_challenge(defender(), 0x1, 0x2, 0x3, 0x4);
}

/// Bond enabled: open_challenge fails when challenger has no balance
#[test]
#[should_panic(expected: ('Insufficient balance',))]
fn test_bond_enabled_open_fails_insufficient_balance() {
    let token_class = declare("MockERC20").unwrap().contract_class();
    let (token_address, _) = token_class.deploy(@array![]).unwrap();
    let token = IMockERC20Dispatcher { contract_address: token_address };
    token.mint(defender(), u256 { low: 1000000000000000000, high: 0 });
    let contract = declare("ChallengeContract").unwrap().contract_class();
    let owner: ContractAddress = 0x1.try_into().unwrap();
    let (challenge_address, _) = contract.deploy(@array![owner.into(), token_address.into()]).unwrap();
    let challenge = IChallengeContractDispatcher { contract_address: challenge_address };
    start_cheat_caller_address(challenge.contract_address, challenger());
    challenge.open_challenge(defender(), 0x1, 0x2, 0x3, 0x4);
}

/// Bond enabled: full flow - challenger opens, defender defends, challenger wins via submit_proof
#[test]
fn test_bond_winner_receives_both_bonds_on_submit_proof() {
    let (challenge, token) = deploy_challenge_with_bonds();

    let mut defender_states: Array<felt252> = array![];
    let mut challenger_states: Array<felt252> = array![];
    let mut i: u32 = 0;
    loop {
        if i >= 256 { break; }
        let sh: felt252 = (i + 1000).into();
        defender_states.append(sh);
        if i < 128 {
            challenger_states.append(sh);
        } else {
            challenger_states.append((sh.into() + 99999).into());
        }
        i += 1;
    };
    let defender_root = build_merkle_root(defender_states.span());
    let challenger_root = build_merkle_root(challenger_states.span());

    start_cheat_caller_address(challenge.contract_address, challenger());
    let challenge_id = challenge.open_challenge(
        defender(), 0xDEF, defender_root, 0xCAFE, challenger_root
    );
    stop_cheat_caller_address(challenge.contract_address);

    start_cheat_caller_address(challenge.contract_address, defender());
    challenge.defend(challenge_id);
    stop_cheat_caller_address(challenge.contract_address);

    let mut round: u8 = 0;
    loop {
        if round >= 8 { break; }
        let ch = challenge.get_challenge(challenge_id);
        let midpoint = (ch.bisection.left + ch.bisection.right) / 2;
        let dm = *defender_states.span().at(midpoint);
        let cm = *challenger_states.span().at(midpoint);
        let dp = generate_merkle_proof(defender_states.span(), midpoint);
        let cp = generate_merkle_proof(challenger_states.span(), midpoint);
        start_cheat_caller_address(challenge.contract_address, defender());
        challenge.bisect(challenge_id, dm, dp.span());
        stop_cheat_caller_address(challenge.contract_address);
        start_cheat_caller_address(challenge.contract_address, challenger());
        challenge.bisect(challenge_id, cm, cp.span());
        stop_cheat_caller_address(challenge.contract_address);
        round += 1;
    };

    let pre = IntegerRegisters {
        r0: 100, r1: 50, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let post = IntegerRegisters {
        r0: 150, r1: 50, r2: 0, r3: 0, r4: 0, r5: 0, r6: 0, r7: 0,
    };
    let proof = default_proof(0, 0, 1, 0, 0, pre, post);

    let challenger_balance_before = token.balance_of(challenger());
    start_cheat_caller_address(challenge.contract_address, challenger());
    challenge.submit_proof(challenge_id, proof);
    stop_cheat_caller_address(challenge.contract_address);

    let challenger_balance_after = token.balance_of(challenger());
    assert(
        challenger_balance_after == challenger_balance_before + BOTH_BONDS,
        'Challenger should receive both bonds'
    );

    let contract_balance = token.balance_of(challenge.contract_address);
    assert(contract_balance == u256 { low: 0, high: 0 }, 'Contract should have zero balance after payout');
}

/// Bond enabled: claim_timeout when defender never defended - challenger gets only challenger_bond
#[test]
fn test_bond_timeout_defender_no_response_challenger_gets_challenger_bond_only() {
    let (challenge, token) = deploy_challenge_with_bonds();

    start_cheat_block_timestamp(challenge.contract_address, 1000);
    start_cheat_caller_address(challenge.contract_address, challenger());
    let challenge_id = challenge.open_challenge(defender(), 0x1, 0x2, 0x3, 0x4);
    stop_cheat_caller_address(challenge.contract_address);

    start_cheat_block_timestamp(challenge.contract_address, 1000 + 14401);
    let challenger_balance_before = token.balance_of(challenger());
    start_cheat_caller_address(challenge.contract_address, challenger());
    challenge.claim_timeout(challenge_id);
    stop_cheat_caller_address(challenge.contract_address);
    stop_cheat_block_timestamp(challenge.contract_address);

    let challenger_balance_after = token.balance_of(challenger());
    assert(
        challenger_balance_after == challenger_balance_before + CHALLENGER_BOND,
        'Challenger should receive only challenger bond (defender never bonded)'
    );
}

/// Bond enabled: claim_timeout when defender defended, challenger times out - defender gets both bonds
#[test]
fn test_bond_timeout_challenger_times_out_defender_gets_both_bonds() {
    let (challenge, token) = deploy_challenge_with_bonds();

    let mut defender_states: Array<felt252> = array![];
    let mut challenger_states: Array<felt252> = array![];
    let mut i: u32 = 0;
    loop {
        if i >= 256 { break; }
        let sh: felt252 = (i + 1000).into();
        defender_states.append(sh);
        challenger_states.append(sh);
        i += 1;
    };
    let defender_root = build_merkle_root(defender_states.span());
    let challenger_root = build_merkle_root(challenger_states.span());

    start_cheat_block_timestamp(challenge.contract_address, 1000);
    start_cheat_caller_address(challenge.contract_address, challenger());
    let challenge_id = challenge.open_challenge(
        defender(), 0xDEF, defender_root, 0xCAFE, challenger_root
    );
    stop_cheat_caller_address(challenge.contract_address);

    start_cheat_caller_address(challenge.contract_address, defender());
    challenge.defend(challenge_id);
    stop_cheat_caller_address(challenge.contract_address);

    let ch = challenge.get_challenge(challenge_id);
    assert(ch.bisection.challenger_turn == true, 'Challenger turn after defend');
    let midpoint = (ch.bisection.left + ch.bisection.right) / 2;
    let dm = *defender_states.span().at(midpoint);
    let dp = generate_merkle_proof(defender_states.span(), midpoint);
    start_cheat_caller_address(challenge.contract_address, defender());
    challenge.bisect(challenge_id, dm, dp.span());
    stop_cheat_caller_address(challenge.contract_address);
    start_cheat_block_timestamp(challenge.contract_address, 1000 + 14401);

    let defender_balance_before = token.balance_of(defender());
    start_cheat_caller_address(challenge.contract_address, defender());
    challenge.claim_timeout(challenge_id);
    stop_cheat_caller_address(challenge.contract_address);
    stop_cheat_block_timestamp(challenge.contract_address);

    let defender_balance_after = token.balance_of(defender());
    assert(
        defender_balance_after == defender_balance_before + BOTH_BONDS,
        'Defender should receive both bonds when challenger times out'
    );
}

/// Bond enabled: contract holds bonds during active challenge
#[test]
fn test_bond_contract_holds_bonds_during_challenge() {
    let (challenge, token) = deploy_challenge_with_bonds();

    start_cheat_caller_address(challenge.contract_address, challenger());
    let challenge_id = challenge.open_challenge(defender(), 0x1, 0x2, 0x3, 0x4);
    stop_cheat_caller_address(challenge.contract_address);

    let contract_balance = token.balance_of(challenge.contract_address);
    assert(
        contract_balance == CHALLENGER_BOND,
        'Contract should hold challenger bond after open'
    );

    start_cheat_caller_address(challenge.contract_address, defender());
    challenge.defend(challenge_id);
    stop_cheat_caller_address(challenge.contract_address);

    let contract_balance_after_defend = token.balance_of(challenge.contract_address);
    assert(
        contract_balance_after_defend == BOTH_BONDS,
        'Contract should hold both bonds after defend'
    );
}

/// Bond enabled: defend fails without defender approval
#[test]
#[should_panic(expected: ('Insufficient allowance',))]
fn test_bond_defend_fails_without_approval() {
    let token_class = declare("MockERC20").unwrap().contract_class();
    let (token_address, _) = token_class.deploy(@array![]).unwrap();
    let token = IMockERC20Dispatcher { contract_address: token_address };
    let mint_amount = u256 { low: 1000000000000000000, high: 0 };
    token.mint(challenger(), mint_amount);
    token.mint(defender(), mint_amount);

    let contract = declare("ChallengeContract").unwrap().contract_class();
    let owner: ContractAddress = 0x1.try_into().unwrap();
    let (challenge_address, _) = contract.deploy(@array![owner.into(), token_address.into()]).unwrap();
    let challenge = IChallengeContractDispatcher { contract_address: challenge_address };

    start_cheat_caller_address(challenge.contract_address, challenger());
    token.approve(challenge_address, u256 { low: 0xFFFFFFFFFFFFFFFF, high: 0xFFFFFFFFFFFFFFFF });
    challenge.open_challenge(defender(), 0x1, 0x2, 0x3, 0x4);
    stop_cheat_caller_address(challenge.contract_address);

    start_cheat_caller_address(challenge.contract_address, defender());
    challenge.defend(1);
}
