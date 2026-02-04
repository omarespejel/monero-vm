# MoneroVM: Fraud Proof Architecture

## Overview

This document describes MoneroVM's fraud proof system for trustless RandomX verification
on Starknet. Inspired by BitVM (Bitcoin), Arbitrum, and Optimism's optimistic verification
patterns.

---

## Primary Use Case: Liveness Failure Recovery

**Scenario**: Alice and Bob are executing an XMR ↔ STRK atomic swap. Bob disappears mid-protocol
after Alice has locked her XMR. Without MoneroVM, Alice's funds are stuck forever.

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATOMIC SWAP LIVENESS FAILURE                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Alice locks XMR to    2. Bob locks STRK    3. Bob disappears │
│     X = X_partial + T        with hashlock        (liveness fail)│
│                                                                  │
│  WITHOUT MoneroVM: Alice's XMR locked forever ❌                 │
│                                                                  │
│  WITH MoneroVM:                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ 4. Alice proves Monero block validity via fraud proof    │   │
│  │ 5. Contract releases Alice's STRK as compensation        │   │
│  │ 6. Alice recovers value trustlessly ✅                   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

This is why MoneroVM exists: **trustless fund recovery when atomic swap counterparties fail**.

---

## Why Fraud Proofs (Not Pure ZK)?

Pure ZK verification of RandomX is **economically impractical**:

| Metric | Pure ZK | Fraud Proofs |
|--------|---------|--------------|
| Cost per hash | ~6.26B Sierra gas | ~0 (unless disputed) |
| Prover time | 10-15 minutes | N/A (native execution) |
| Dispute cost | N/A | ~1K constraints |
| Trust model | Cryptographic | Economic + cryptographic |

**Auditor's verdict**: "Fraud proofs are strongly recommended for production deployment."

---

## Architecture: Hybrid Attestation + Fraud Proofs

```
┌─────────────────────────────────────────────────────────────────┐
│                       NORMAL FLOW (99.9%)                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   User submits      Relayer quorum       Claim accepted         │
│   RandomX claim  →  attests validity  →  immediately            │
│                                                                 │
│   Time: ~seconds    Cost: minimal        Trust: quorum          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      DISPUTED FLOW (0.1%)                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Challenger        Bisection          Single instruction       │
│   disputes claim →  protocol       →   ZK proof resolves        │
│                                                                 │
│   Bond: 0.1 ETH     Rounds: ~22        Cost: ~1K constraints    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## State Commitment Scheme

### RandomX VM State

```
State = {
    registers: {
        r0-r7: [u64; 8],      // Integer registers (64 bytes)
        f0-f3: [f64x2; 4],    // F group registers (64 bytes)
        e0-e3: [f64x2; 4],    // E group registers (64 bytes)
        a0-a3: [f64x2; 4],    // A group registers (64 bytes)
    },
    memory: {
        scratchpad: [u8; 2MB], // L3 scratchpad
        ma: u32,               // Memory address register
        mx: u32,               // Memory address register
    },
    execution: {
        pc: u32,               // Program counter
        ic: u32,               // Iteration counter
        program_idx: u8,       // Current program (0-7)
        fprc: u2,              // Floating-point rounding control
    }
}
```

### State Hash Computation

```cairo
fn compute_state_hash(state: RandomXState) -> felt252 {
    // Hash registers directly (small, ~256 bytes)
    let reg_hash = poseidon_hash_many(state.registers.to_felts());
    
    // Hash scratchpad as Merkle root (2MB → single root)
    let scratchpad_root = compute_merkle_root(state.scratchpad);
    
    // Combine all state components
    poseidon_hash(
        reg_hash,
        scratchpad_root,
        state.pc.into(),
        state.ic.into(),
        state.program_idx.into(),
        state.fprc.into(),
        state.ma.into(),
        state.mx.into()
    )
}
```

### Scratchpad Merkle Tree

```
Structure: Binary Merkle tree over 2MB scratchpad
- Leaf size: 64 bytes (aligned with RandomX access pattern)
- Number of leaves: 2MB / 64B = 32,768 leaves
- Tree depth: log2(32,768) = 15 levels
- Hash function: Poseidon (491 gas per hash)

Cost per proof: 15 × 491 = ~7,365 Sierra gas
```

---

## Bisection Protocol

### Hierarchical Bisection (22 rounds)

```
PHASE 1: Program-level bisection (3 rounds)
─────────────────────────────────────────
8 programs → 4 → 2 → 1
Each round: commit to state after N programs

PHASE 2: Iteration-level bisection (11 rounds)
─────────────────────────────────────────
2048 iterations → 1024 → 512 → ... → 1
Each round: commit to state after N iterations

PHASE 3: Instruction-level bisection (8 rounds)
─────────────────────────────────────────
256 instructions → 128 → 64 → ... → 1
Final round: prove single instruction execution
```

### Bisection Contract Interface

```cairo
#[starknet::interface]
trait IFraudProof<TContractState> {
    // Initiate a challenge against a claim
    fn challenge(
        ref self: TContractState,
        claim_id: felt252,
        challenger_state_hash: felt252
    );
    
    // Submit bisection response
    fn bisect(
        ref self: TContractState,
        challenge_id: felt252,
        left_state_hash: felt252,
        right_state_hash: felt252
    );
    
    // Submit final single-instruction proof
    fn prove_instruction(
        ref self: TContractState,
        challenge_id: felt252,
        pre_state: RandomXState,
        instruction: RandomXInstruction,
        post_state: RandomXState,
        merkle_proofs: Array<MerkleProof>
    );
    
    // Claim timeout victory
    fn claim_timeout(
        ref self: TContractState,
        challenge_id: felt252
    );
}
```

---

## Single Instruction Verification

### Instruction Categories

| Category | Instructions | Verification Complexity |
|----------|--------------|------------------------|
| Integer ALU | IADD, ISUB, IMUL, IXOR, etc. | Simple (~50 constraints) |
| Integer MUL high | IMULH_R, ISMULH_R | Medium (~200 constraints) |
| Rotate/Shift | IROR_R, IROL_R | Simple (~30 constraints) |
| Memory Load | IADD_M, ISUB_M, etc. | + Merkle proof (~500 constraints) |
| Memory Store | ISTORE | + Merkle proof (~500 constraints) |
| **Floating Point** | FADD, FSUB, FMUL, FDIV, FSQRT | **Complex (~2000 constraints)** |
| Control Flow | CBRANCH, CFROUND | Medium (~100 constraints) |

### Example: IMULH_R Verification

```cairo
fn verify_imulh_r(
    pre_state: RegisterFile,
    dst: u8,
    src: u8,
    post_state: RegisterFile
) -> bool {
    // Get operands
    let a: u64 = pre_state.r[dst];
    let b: u64 = pre_state.r[src];
    
    // Compute expected result (high 64 bits of 128-bit product)
    let product: u128 = a.into() * b.into();
    let expected: u64 = (product / 0x10000000000000000).try_into().unwrap();
    
    // Verify post_state
    let mut expected_state = pre_state;
    expected_state.r[dst] = expected;
    
    post_state == expected_state
}
```

### Example: Memory Load with Merkle Proof

```cairo
fn verify_iadd_m(
    pre_state: FullState,
    dst: u8,
    src: u8,
    imm32: i32,
    post_state: FullState,
    merkle_proof: MerkleProof
) -> bool {
    // Calculate memory address
    let addr = compute_address(pre_state.registers.r[src], imm32, pre_state.mod_mem);
    
    // Verify Merkle proof for memory read
    let mem_value = verify_merkle_read(
        pre_state.scratchpad_root,
        addr,
        merkle_proof
    );
    
    // Compute expected result
    let expected = wrapping_add_64(pre_state.registers.r[dst], mem_value);
    
    // Verify post_state
    post_state.registers.r[dst] == expected
}
```

---

## Bond and Timeout Parameters

### Economic Security

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Challenger bond | 0.1 ETH (~$200) | Prevents spam challenges |
| Defender bond | 0.2 ETH (~$400) | Higher stake for claimer |
| Minimum swap value | $100 | Below this, attestation-only |
| Maximum swap value | $100K | Above this, require full ZK? |

### Timeout Schedule

| Phase | Timeout | Rationale |
|-------|---------|-----------|
| Challenge window | 24 hours | Allow time to detect fraud |
| Bisection response | 4 hours | Account for offline parties |
| Final proof | 24 hours | ZK proof generation time |
| Total dispute | 7 days | Arbitrum standard |

### Timeout Handling

```cairo
fn handle_timeout(challenge: Challenge) {
    let current_time = get_block_timestamp();
    let deadline = challenge.last_action_time + challenge.current_timeout;
    
    if current_time > deadline {
        // Whoever's turn it was loses
        if challenge.current_turn == Turn::Defender {
            // Defender failed to respond → challenger wins
            slash_defender(challenge);
            reward_challenger(challenge);
        } else {
            // Challenger failed to respond → defender wins
            slash_challenger(challenge);
            reward_defender(challenge);
        }
    }
}
```

---

## Implementation Phases

### Phase 1: MVP (Week 1-2)

| Component | Description | Priority |
|-----------|-------------|----------|
| State hash | Poseidon-based state commitment | P0 |
| Single-instruction verifier | IMULH, IADD, ISUB, IXOR | P0 |
| Challenge contract | Basic challenge/response | P0 |
| Bond handling | Lock/slash/reward | P0 |

**Scope**: No bisection, disputes go directly to instruction-level proof.

### Phase 2: Full Protocol (Week 3-4)

| Component | Description | Priority |
|-----------|-------------|----------|
| Hierarchical bisection | 22-round protocol | P1 |
| All instruction verifiers | 29 instruction types | P1 |
| Automated challenger | Off-chain monitoring | P1 |
| Gas optimizations | Batch proofs, caching | P2 |

### Phase 3: Production Hardening (Week 5+)

| Component | Description | Priority |
|-----------|-------------|----------|
| Security audit | External review | P0 |
| Mainnet deployment | Gradual rollout | P1 |
| Monitoring dashboard | Real-time alerts | P2 |
| Documentation | User guides, API docs | P2 |

---

## Integration with Existing Attestation System

### Contract Modifications

```cairo
#[starknet::contract]
mod AtomicSwapWithFraudProof {
    // Existing attestation logic
    use super::attestation::{verify_quorum, RelayerRegistry};
    
    // New fraud proof logic
    use super::fraud_proof::{FraudProofState, verify_instruction};
    
    #[storage]
    struct Storage {
        // Existing
        claims: LegacyMap<felt252, Claim>,
        attestations: LegacyMap<felt252, AttestationSet>,
        
        // New
        challenges: LegacyMap<felt252, Challenge>,
        fraud_proof_enabled: bool,
    }
    
    fn submit_claim(ref self: ContractState, claim: Claim) {
        // Normal attestation flow
        if self.fraud_proof_enabled {
            // Start challenge window
            self.claims.write(claim.id, claim);
            self.emit(ClaimSubmitted { claim_id: claim.id, challenge_deadline: ... });
        } else {
            // Legacy: immediate attestation acceptance
            self.process_attestation(claim);
        }
    }
}
```

---

## Security Considerations

### Critical: Collusion Prevention (PRT)

**Attack Identified by Auditor**:
```
1. Malicious attester submits false claim
2. Colluding "challenger" initiates fake dispute
3. Challenger intentionally loses
4. False claim gets "validated" via rigged dispute
```

**Solution: Permissionless Refereed Tournaments (PRT)**

The key insight from BoLD/Dave research: once you commit to a computation trace root,
all bisection moves must be Merkle-provable against it. A challenger cannot lie about
intermediate states because the proof will fail.

```cairo
// PRT-style bisection - challenger cannot intentionally lose
fn bisect(claim: Claim, midpoint: u64, proof: MerkleProof) {
    // Verify midpoint is consistent with original trace root
    assert!(verify_merkle(claim.trace_root, midpoint, proof));
    // Now challenger cannot claim false intermediate states
}
```

| Property | Old Design | PRT Design |
|----------|------------|------------|
| Can challenger throw game? | Yes ❌ | **No** ✅ |
| Mechanism | Trust | Merkle proofs |
| Security model | Economic | Cryptographic |

### Attack Vectors

| Attack | Mitigation |
|--------|------------|
| Griefing (spam challenges) | Challenger bond (0.1 ETH) |
| Stalling (slow responses) | Timeout slashing |
| **Collusion (fake disputes)** | **PRT-style Merkle proofs** ✅ |
| Front-running | Commit-reveal for challenges |

### Assumptions

1. **At least one honest challenger** monitors claims
2. **Liveness**: Parties respond within timeout
3. **Correct off-chain execution**: RandomX runs correctly natively
4. **Merkle proof soundness**: Poseidon hash collision resistance

### Failure Modes

| Failure | Impact | Recovery |
|---------|--------|----------|
| No challengers | False claims accepted | Increase rewards |
| All challengers offline | Window expires, claim accepted | Manual intervention |
| Prover bug | Incorrect disputes | Upgrade contract |
| **Collusion attempt** | **Blocked by PRT proofs** | N/A - attack fails |

---

## References

- [Arbitrum BoLD](https://docs.arbitrum.io/how-arbitrum-works/bold)
- [Optimism Fault Proofs](https://docs.optimism.io/stack/protocol/fault-proofs)
- [RandomX Specification](https://github.com/tevador/RandomX/blob/master/doc/specs.md)
- [Starknet Fee Structure](https://docs.starknet.io/learn/protocol/fees)
