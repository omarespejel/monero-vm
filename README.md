# MoneroVM

**Trustless Monero verification on Starknet via fraud proofs.**

[![Tests](https://img.shields.io/badge/tests-644%20passing-brightgreen)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Network](https://img.shields.io/badge/network-Sepolia%20Testnet-orange)]()

> **License: Apache 2.0 — Attribution and citation required.**
> If you use, fork, or build upon this code, you **must** include the [LICENSE](LICENSE) and [NOTICE](NOTICE) files and cite this project. Academic publications and derivative works **must** include the citation below. See [NOTICE](NOTICE) for full terms.
>
> ```
> Espejel, O. (2025). "MoneroVM: Optimistic RandomX Execution Verification
> via Fraud Proofs on Starknet."
> https://github.com/omarespejel/monero-vm
> ```

---

## Overview

MoneroVM is the first implementation of RandomX fraud proof verification on a smart contract platform. It enables trustless verification of Monero block headers on Starknet through optimistic execution with on-chain dispute resolution.

**Key Innovation**: Rather than proving entire RandomX computations in ZK (which costs ~$600/hash), MoneroVM uses BitVM-inspired fraud proofs to verify disputed executions at ~$0.08/dispute.

---

## Testnet Deployment

| Network | Contract Address |
|---------|------------------|
| **Starknet Sepolia** | [`0x034ee50aa710e360c793ec9a989438c9f790be90dbc19b2c302ade5263f835b6`](https://sepolia.starkscan.co/contract/0x034ee50aa710e360c793ec9a989438c9f790be90dbc19b2c302ade5263f835b6) |

---

## Why Fraud Proofs?

Pure ZK verification of RandomX is economically impractical:

| Approach | Cost | Practical? |
|----------|------|------------|
| Pure ZK | ~$600/hash | No |
| **Fraud Proofs** | **~$0.08/dispute** | **Yes** |

RandomX's 29-instruction VM with IEEE-754 floating-point and 2MB memory makes ZK proving extremely expensive (~6.26B Sierra gas). Fraud proofs achieve the same security guarantees at a fraction of the cost.

---

## Features

### Complete RandomX Instruction Coverage

All 29 RandomX opcodes verified on-chain:

| Category | Instructions | Status |
|----------|--------------|--------|
| Integer Arithmetic | IADD_R, ISUB_R, IMUL_R, IMULH_R, ISMULH_R, IXOR_R, IROR_R, IROL_R, INEG_R | ✅ |
| Integer Special | IMUL_RCP, IADD_RS, ISWAP_R, NOP | ✅ |
| Memory Operations | IADD_M, ISUB_M, IMUL_M, IMULH_M, ISMULH_M, IXOR_M, ISTORE | ✅ |
| Floating-Point | FADD_R/M, FSUB_R/M, FMUL_R, FDIV_M, FSQRT_R, FSCAL_R, CFROUND | ✅ |
| Control Flow | CBRANCH | ✅ |

### IEEE-754 Floating-Point Verification

- Full double precision (64-bit)
- All 4 rounding modes (ties-to-even, toward-negative, toward-positive, toward-zero)
- Special case handling: NaN, ±Infinity, ±0, subnormals
- Witness-based verification for complex operations

### Dispute Resolution

- **Bisection Protocol**: Binary search to single disputed instruction (11 rounds for 2048 instructions)
- **Gas Costs**: 15K-391K per instruction verification
- **Total Dispute**: ~787K L2 gas

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    MoneroVM Fraud Proof System                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  CLAIMED EXECUTION              CHALLENGE CONTRACT               │
│  ┌────────────────────┐        ┌────────────────────────────┐   │
│  │ Off-chain RandomX  │        │ open_challenge()           │   │
│  │ State commitments  │  ───►  │ bisect()                   │   │
│  │ Merkle roots       │ dispute│ submit_proof()             │   │
│  └────────────────────┘        │ claim_timeout()            │   │
│                                └────────────────────────────┘   │
│                                                                  │
│  INSTRUCTION VERIFIERS                                          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Integer: IADD, ISUB, IMUL, IMULH, ISMULH, IXOR, IROR, IROL │ │
│  │ Memory:  *_M variants with Merkle proof verification       │ │
│  │ FP:      IEEE-754 compliant with witness-based proofs      │ │
│  │ Control: CBRANCH with register modification tracking       │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- [Scarb](https://docs.swmansion.com/scarb/) 2.11.4+ (Cairo package manager)
- [Starknet Foundry](https://foundry-rs.github.io/starknet-foundry/) (for testing)

### Build & Test

```bash
# Clone the repository
git clone https://github.com/omarespejel/monero-vm.git
cd monero-vm

# Build
scarb build

# Run tests (644 tests)
snforge test
```

### Interact with Testnet Contract

```bash
# Check challenge count
sncast call \
  --contract-address 0x034ee50aa710e360c793ec9a989438c9f790be90dbc19b2c302ade5263f835b6 \
  --function get_challenge_count \
  --network sepolia

# Open a challenge (requires funded account)
sncast invoke \
  --contract-address 0x034ee50aa710e360c793ec9a989438c9f790be90dbc19b2c302ade5263f835b6 \
  --function open_challenge \
  --arguments 'DEFENDER, DEFENDER_HASH, DEFENDER_TRACE, CHALLENGER_HASH, CHALLENGER_TRACE' \
  --network sepolia
```

---

## Gas Benchmarks

| Operation | L2 Gas | Category |
|-----------|--------|----------|
| IADD_R, ISUB_R | ~16K | Simple |
| IMUL_R, IMULH_R | ~20K | Simple |
| CBRANCH | ~40K | Control |
| IROR_R, IROL_R | ~335K | Complex |
| Memory + Merkle | ~387K | Memory |
| State Hash | ~403K | State |
| **Full Dispute** | **~787K** | Total |

---

## Documentation

| Document | Description |
|----------|-------------|
| [PAPER_OUTLINE.md](docs/PAPER_OUTLINE.md) | Research paper for Monero Research Lab |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Fraud proof system architecture |
| [SECURITY_NOTES.md](docs/SECURITY_NOTES.md) | Security considerations and edge cases |
| [RESEARCH_NOTES.md](docs/RESEARCH_NOTES.md) | ZK feasibility analysis |
| [IMPLEMENTATION_GUIDE.md](docs/IMPLEMENTATION_GUIDE.md) | How to verify Monero on Starknet |
| [ROADMAP.md](docs/ROADMAP.md) | Project roadmap |

---

## Project Structure

```
monero-vm/
├── src/
│   ├── lib.cairo              # Library root
│   ├── challenge.cairo        # Challenge contract (main entry point)
│   └── randomx/
│       ├── fraud_proof.cairo  # Instruction verifiers + IEEE-754
│       ├── blake2b.cairo      # Blake2b implementation
│       ├── aes.cairo          # AES operations
│       └── merkle_verification.cairo
├── tests/
│   ├── test_challenge.cairo   # Contract integration tests
│   ├── test_fraud_proof.cairo # Verifier unit tests
│   └── test_randomx_edge_cases.cairo
├── docs/                      # Documentation
└── scripts/                   # Deployment and utility scripts
```

---

## Security

### External Audits Referenced

MoneroVM builds on audited components and follows findings from external security reviews:

#### RandomX Algorithm

| Auditor | Date | Report | Findings Applied |
|---------|------|--------|------------------|
| X41 D-Sec | June 2019 | [Report](https://x41-dsec.de/static/reports/X41-RandomX-Audit-2019-Final-Report-Public.pdf) | Memory verification patterns |
| Trail of Bits | June 2019 | [Report](https://x41-dsec.de/static/reports/X41-RandomX-Audit-2019-Final-Report-Public.pdf) | Merkle proof verification |
| Kudelski Security | July 2019 | [Report](https://ostif.org/wp-content/uploads/2019/08/Report-Kudelski-201907022.pdf) | IMUL_RCP edge cases, cryptographic validation |

#### Cairo Dependencies

| Component | Source | Audit |
|-----------|--------|-------|
| Blake2b | [Herodotus/integrity](https://github.com/HerodotusDev/integrity) | [zksecurity audit](https://github.com/HerodotusDev/integrity/tree/main/audit) |

### Implementation Notes

- **644 tests** covering all instruction verifiers and edge cases
- IEEE-754 special cases: NaN, Infinity, zero, subnormals
- All 4 rounding modes tested
- Memory operations with Merkle proof verification
- CBRANCH register modification tracking

---

## Contributing

Contributions are welcome! Please read the documentation and ensure all tests pass before submitting a PR.

```bash
# Run tests before submitting
snforge test

# Check for linting issues
scarb fmt --check
```

---

## Related Projects

| Repository | Description |
|------------|-------------|
| [monero-starknet-atomic-swap](https://github.com/omarespejel/monero-starknet-atomic-swap) | Atomic swap protocol: DLEQ proofs, two-party key generation, AtomicLock contract |

**Together these repos enable trustless Monero ↔ Starknet atomic swaps:**
- **monero-starknet-atomic-swap**: Handles the swap protocol (adaptor signatures, hashlock contracts)
- **monero-vm**: Verifies RandomX computation disputes (fraud proofs for Monero block validation)

---

## References

- [RandomX Specification](https://github.com/tevador/RandomX/blob/master/doc/specs.md)
- [BitVM Whitepaper](https://bitvm.org/bitvm.pdf) - Inspiration for fraud proof design
- [Arbitrum Fraud Proofs](https://developer.arbitrum.io/inside-arbitrum-nitro/) - Similar L2 approach
- [RFC 7693 - Blake2](https://datatracker.ietf.org/doc/html/rfc7693)

---

## License

Apache-2.0

---

## Acknowledgments

- [tevador](https://github.com/tevador) for the RandomX specification and reference implementation
- [Herodotus](https://github.com/HerodotusDev/integrity) for audited Cairo cryptographic primitives
- [Garaga](https://github.com/keep-starknet-strange/garaga) for elliptic curve operations
