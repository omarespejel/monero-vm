# M2 FP Verification Audit Report — MoneroVM

I conducted a review of the RandomX source code, specs, and relevant implementations. Below are findings and recommendations for M2 floating-point verification.

## 1. Test Vector Generation (RandomX Reference)

### Recommended Approach
Based on `vm_interpreted.cpp` and `bytecode_machine.hpp`, the best approach is to instrument the interpreter directly.

1) Instrument `vm_interpreted.cpp` — hook into `executeBytecode()` to dump pre/post FP register states. Capture:
- `nreg.f[i]` (F group registers — additive operations)
- `nreg.e[i]` (E group registers — multiplicative operations)
- `nreg.a[i]` (A group registers — read-only source operands)

2) Log FPRC values — log `fprc` transitions from CFROUND. The 2-bit `fprc` determines rounding mode for all subsequent FP operations. CFROUND frequency is 1/256, but it affects every FP op after it executes.

3) Memory operands — for FADD_M / FSUB_M / FDIV_M, log:
- Raw 8-byte value from scratchpad
- Converted `rx_vec_f128` after `rx_cvt_packed_int_vec_f128()`
- Memory address (for reproducibility)

### Edge Cases to Cover
The RandomX spec states no operation results in NaN or a denormal number due to register restrictions. The witness verifier should still handle:
- Signed zeros (e.g., `+0.0 - +0.0` in rounding mode 1 yields `-0.0`)
- Infinity handling (E group registers can reach infinity through FMUL_R/FDIV_M chains)
- Rounding mode transitions (test vectors for all 4 modes)
- E group masking (`maskRegisterExponentMantissa()` restricts divisor ranges for FDIV_M)

References:
- RandomX interpreter: https://github.com/tevador/RandomX/blob/master/src/vm_interpreted.cpp
- RandomX spec FP ops: https://github.com/tevador/RandomX/blob/master/doc/specs.md#43-floating-point-operations
- Bytecode machine: https://github.com/tevador/RandomX/blob/master/src/bytecode_machine.hpp

---

## 2. FP Instruction Order / Priority

### Exact Frequencies (per 256 opcodes)

| Instruction | Frequency | % |
|-------------|-----------|---|
| FMUL_R | 32/256 | 12.5% |
| FADD_R | 16/256 | 6.3% |
| FSUB_R | 16/256 | 6.3% |
| FSQRT_R | 6/256 | 2.3% |
| FSCAL_R | 6/256 | 2.3% |
| FADD_M | 5/256 | 2.0% |
| FSUB_M | 5/256 | 2.0% |
| FSWAP_R | 4/256 | 1.6% |
| FDIV_M | 4/256 | 1.6% |
| CFROUND | 1/256 | 0.4% |

Reference: https://github.com/tevador/RandomX/blob/master/src/configuration.h

### Recommended Implementation Order

1) FSCAL_R — simplest (bitwise XOR with `0x80F0000000000000`). No rounding, no arithmetic. Use to validate the witness/verification pipeline.
2) FSQRT_R — deterministic unary operation. Uses `fprc`, no memory operand.
3) FMUL_R — highest frequency; simpler than add/sub (no alignment shift).
4) FADD_R / FSUB_R — require exponent alignment; `alignment_shift` witness is critical.
5) FADD_M / FSUB_M / FDIV_M — memory operands add conversion complexity (`rx_cvt_packed_int_vec_f128`).
6) FSWAP_R — trivial swap.

Rationale: start with FSCAL_R to validate plumbing without rounding complexity, then FSQRT_R for rounding, then FMUL_R for frequency, then add/sub for alignment, then memory ops.

---

## 3. Witness Structure Analysis

Current `FPWitness` struct is solid. Based on SChernykh’s soft-float implementation, keep the full extended mantissa.

### Keep full extended mantissa (72+ bits)
- Full precision needed during intermediate multiplication (128-bit product)
- Proper alignment tracking for exponent differences
- GRS bits required for correct rounding

Reference: https://github.com/SChernykh/RandomX_OpenCL/blob/master/RandomX_OpenCL/CL/randomx_vm.cl

### Suggested Witness Fields

```solidity
struct FPWitness {
    // Existing fields
    uint256 extended_mantissa_hi;
    uint256 extended_mantissa_lo;
    uint256 rounding_adjustment;
    uint8 guard_round_sticky;  // 3 bits packed
    int16 result_exponent;
    int8 normalization_shift;
    int8 alignment_shift;      // Critical for FADD/FSUB

    // Suggested additions
    uint8 fprc_at_execution;   // 2-bit rounding mode at execution
    uint8 sign_a;              // Source operand sign
    uint8 sign_b;
    bool overflow_flag;        // Infinity detection
}
```

Missing field alert: `fprc_at_execution` — rounding mode can change mid-program via CFROUND, so the verifier must know the active mode per instruction.

---

## 4. Gas Targets

~1M gas per FP instruction is acceptable for initial implementation.

Context:
- Bisection protocol is ~71M gas for full flow
- 94/256 opcodes are FP (36.7%)
- 256-instruction program → ~94 FP ops
- At 1M gas each, worst-case single-step verification is ~94M gas

### Optimization Priority (if needed)
1) Mantissa alignment — precompute off-chain; verify via witness
2) Normalization — use CLZ-based tricks instead of loops
3) Rounding logic — SChernykh shows rounding can be reduced to a few conditionals based on GRS bits and mode

Critical insight: `fma_soft` shows you only need soft-float for final rounding; use hardware FMA where rounding is ties-to-even, then apply correction via fprc. This can reduce gas for FMUL_R and FADD/FSUB.

Reference: https://github.com/SChernykh/RandomX_OpenCL/blob/master/RandomX_OpenCL/CL/randomx_vm.cl

---

## 5. Additional Recommendations

1) Reference the X41 and Kudelski audits — both validate RandomX FP semantics; no exploitable FP edge cases in core algorithm.
2) Test against SChernykh’s OpenCL implementation — production soft-float with correct rounding modes.
3) Document the fprc state machine — CFROUND changes rounding until next CFROUND or program end.
4) Verify E-group masking — `maskRegisterExponentMantissa()` ensures divisors in FDIV_M are never zero/subnormal.

References:
- X41 D-Sec report: https://x41-dsec.de/static/reports/X41-RandomX-Audit-2019-Final-Report-Public.pdf
- RandomX OpenCL: https://github.com/SChernykh/RandomX_OpenCL/blob/master/RandomX_OpenCL/CL/randomx_vm.cl
- RandomX spec: https://github.com/tevador/RandomX/blob/master/doc/specs.md

---

If you want deeper dives or actual test vectors extracted from the reference implementation, I can generate and attach them.

---

## Implementation Status (2026-02-02)

We implemented the FP trace pipeline and integrated it with MoneroVM test vectors.

### What’s in place

- RandomX reference instrumentation (JSONL FP trace) in `${RANDOMX_DIR:-../RandomX}`:
  - `src/trace_fp.hpp`, `src/trace_fp.cpp` (trace writer + witness fields)
  - `src/bytecode_machine.hpp` (FP op + CFROUND hooks)
  - `src/bytecode_machine.cpp` (register metadata for trace)
  - `src/vm_interpreted.cpp` (trace header/footer)
  - CMake flag: `RANDOMX_TRACE_FP`
  - Tool: `randomx-fp-trace` (new CLI)

- MoneroVM vector pipeline:
  - `tools/generate_fp_vectors.py` consumes JSONL trace and emits Cairo vectors
  - `tools/run_fp_vector_pipeline.sh` builds RandomX, runs trace, generates Cairo vectors
  - Output (generated): `tests/test_fp_vectors.cairo`
  - `tools/split_fp_trace.py` splits per-opcode JSON files into `test_vectors/`

- Correctness fix:
  - `FSCAL_R` verifier updated to target F-group (f0–f3), consistent with RandomX spec.

### How to run the pipeline

```
tools/run_fp_vector_pipeline.sh
```

### Notes on witness completeness

The tracer now emits mantissa/exponent/sign, alignment shift, extended mantissa (best-effort), and GRS bits for FADD/FSUB/FMUL. FDIV/FSQRT witness fields are emitted but do not yet compute full intermediate values. This is sufficient to validate plumbing and expand incrementally; full precision witness for FDIV/FSQRT can be added next.

### OpenCL Cross-Validation (Optional)

We added an optional validation script that builds and runs SChernykh’s RandomX_OpenCL tests:

```
tools/run_opencl_validation.sh
```

This requires a compatible GPU, OpenCL runtime, and `clrxasm` (CLRadeonExtender).

**TODO**: Run OpenCL cross‑validation when compatible hardware is available.
