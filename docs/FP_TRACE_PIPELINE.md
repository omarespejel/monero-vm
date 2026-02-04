# FP Trace Pipeline (RandomX → MoneroVM)

This document describes the end-to-end pipeline used to generate floating‑point (FP) test vectors for MoneroVM from the RandomX reference implementation.

## Overview

1) Instrument RandomX (interpreted VM) to emit FP operations as JSONL.
2) Run the tracer on a known seed/input to produce `fp_trace.jsonl`.
3) Convert the trace into Cairo test vectors for MoneroVM.

## Locations

- RandomX reference repo: `${RANDOMX_DIR:-../RandomX}`
- Trace output: `tools/fp_trace.jsonl`
- Generator: `tools/generate_fp_vectors.py`
- Cairo vectors (generated, not committed): `tests/test_fp_vectors.cairo`
- Canonical audit vectors (checked in): `tests/vectors/canonical/`

## Build + Run (one command)

```
tools/run_fp_vector_pipeline.sh
```

This script:
- Builds RandomX with `RANDOMX_TRACE_FP=ON`
- Runs `randomx-fp-trace` to write JSONL
- Generates Cairo vectors from the trace
- Splits the trace into per-opcode JSONL files in `test_vectors/`

## Manual Run

```
${RANDOMX_DIR:-../RandomX}/build-trace/randomx-fp-trace \
  --seed-hex 0x... \
  --input-hex 0x... \
  --out /path/to/fp_trace.jsonl

python3 tools/generate_fp_vectors.py \
  --trace /path/to/fp_trace.jsonl \
  --out tests/test_fp_vectors.cairo

python3 tools/split_fp_trace.py \
  --trace /path/to/fp_trace.jsonl \
  --out-dir test_vectors
```

## JSONL Schema (abbreviated)

Each FP op emits one record per lane:

```
{"type":"fp_op","pc":42,"opcode":"FMUL_R","dst_reg":"e0","src_reg":"a2","lane":0,
 "fprc":0,"pre_dst":"0x...","pre_src":"0x...","post_dst":"0x...",
 "witness":{"mantissa_a":"0x...","mantissa_b":"0x...","exp_a":1025,"exp_b":1028,
 "sign_a":0,"sign_b":0,"alignment_shift":3,"extended_mantissa_hi":"0x...",
 "extended_mantissa_lo":"0x...","grs":"0b101","rounding_applied":false,
 "normalization_shift":1,"result_exponent":1030,"fprc_at_execution":0}}
```

Header includes the RandomX git SHA (from the local reference repo):

```
{"type":"header","randomx_version":"<git-sha>","program_seed":"0x...","fprc_initial":0}
```

CFROUND emits a separate record:

```
{"type":"cfround","pc":87,"src_reg":"r3","src_value":"0x...","imm":17,
 "rotation_result":"0x...","pre_fprc":0,"post_fprc":2}
```

## Witness Coverage Notes

- FADD/FSUB/FMUL: mantissas, alignment shift, extended mantissa, and GRS bits are emitted.
- FDIV: extended mantissa and GRS bits are emitted via fixed‑point long division.
- FSQRT: extended mantissa is derived from the result mantissa (GRS = 0). This is sufficient for
  trace plumbing; full sqrt witness can be added later if needed.

## TODO (Optional)

- Run OpenCL cross‑validation once a compatible GPU + OpenCL runtime + `clrxasm` are available:
  `tools/run_opencl_validation.sh`

## Spec Alignment

- `FSCAL_R` operates on **F‑group** registers (f0–f3). MoneroVM verifier and tests were updated accordingly.

## Relevant Files

RandomX:
- `src/trace_fp.hpp`, `src/trace_fp.cpp`
- `src/bytecode_machine.hpp`
- `src/bytecode_machine.cpp`
- `src/vm_interpreted.cpp`
- `src/tests/fp-trace.cpp`
- `CMakeLists.txt` (flag + target)

MoneroVM:
- `tools/generate_fp_vectors.py`
- `tools/run_fp_vector_pipeline.sh`
- `tools/split_fp_trace.py` (writes per-opcode JSONL)
- `tools/run_opencl_validation.sh`
- `tests/test_fp_vectors.cairo` (generated)
- `tests/test_fp_vectors_canonical.cairo` (canonical vectors)
- `src/randomx/fraud_proof.cairo` (FSCAL_R verifier)
- `tests/test_fraud_proof.cairo` (FSCAL_R tests)
