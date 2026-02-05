# Auditor Status Report — M2 FP Verification (MoneroVM)

Date: 2026-02-03

## Summary (What’s Done)

We implemented an end‑to‑end FP trace + test‑vector pipeline backed by the RandomX reference interpreter, and wired it into MoneroVM tests. We also fixed a spec mismatch in FSCAL_R (F‑group) and added optional OpenCL cross‑validation tooling.

## Fixes Applied (Audit v2)

- FTZ/DAZ replication: denormals flush to signed zero in verifier, witness records `ftz_daz_active = 1`.
- FSUB cancellation hardened: subtraction witness now validates GRS + extended mantissa and checks sign flip on borrow.
- Added FTZ/DAZ edge‑case vectors (denormal inputs) in the generated FP vector suite.
- Added signed-zero rounding vectors + unit tests (round-toward-negative vs ties-to-even).
- Added FDIV near-zero divisor boundary vectors (min E-group divisor, max numerator).

## Key Implementations

### RandomX Reference Instrumentation (Truth Source)
Location: `${RANDOMX_DIR:-../RandomX}`

- **JSONL trace writer** with header/footer and FP op records
  - `src/trace_fp.hpp`, `src/trace_fp.cpp`
- **FP op hooks + CFROUND tracing**
  - `src/bytecode_machine.hpp`
- **Register metadata for trace**
  - `src/bytecode_machine.cpp`
- **Trace init/footer in interpreted VM**
  - `src/vm_interpreted.cpp`
- **Build flag + CLI tool**
  - `RANDOMX_TRACE_FP` in `CMakeLists.txt`
  - `randomx-fp-trace` tool in `src/tests/fp-trace.cpp`

#### Code Snippets (RandomX Reference)

**1) FP op trace hook (bytecode_machine.hpp)**
```cpp
// Example: FADD_R instrumentation (similar pattern for FSUB_R/FMUL_R/FDIV_M/FSQRT_R)
static void exe_FADD_R(RANDOMX_EXE_ARGS) {
#ifdef RANDOMX_TRACE_FP
    uint64_t pre_dst_lo = 0;
    uint64_t pre_dst_hi = 0;
    uint64_t pre_src_lo = 0;
    uint64_t pre_src_hi = 0;
    if (trace_fp_enabled()) {
        trace_vec_pair(*ibc.fdst, pre_dst_lo, pre_dst_hi);
        trace_vec_pair(*ibc.fsrc, pre_src_lo, pre_src_hi);
    }
#endif
    *ibc.fdst = rx_add_vec_f128(*ibc.fdst, *ibc.fsrc);
#ifdef RANDOMX_TRACE_FP
    if (trace_fp_enabled()) {
        uint64_t post_lo = 0;
        uint64_t post_hi = 0;
        trace_vec_pair(*ibc.fdst, post_lo, post_hi);
        trace_fp_lane_ops("FADD_R", ibc, pc, pre_dst_lo, pre_dst_hi, pre_src_lo, pre_src_hi, post_lo, post_hi, false, 0, 0, 0, 0);
    }
#endif
}
```

**2) CFROUND trace (bytecode_machine.hpp)**
```cpp
static void exe_CFROUND(RANDOMX_EXE_ARGS) {
#ifdef RANDOMX_TRACE_FP
    uint32_t pre_fprc = rx_get_rounding_mode();
#endif
    uint64_t src_value = *ibc.isrc;
    uint64_t rot = rotr(src_value, ibc.imm);
    uint32_t post_fprc = static_cast<uint32_t>(rot % 4);
    rx_set_rounding_mode(post_fprc);
#ifdef RANDOMX_TRACE_FP
    if (trace_fp_enabled()) {
        char src_name[4] = {0};
        trace_reg_name(src_name, 'r', ibc.trace_src_index);
        trace_cfround(pc, src_name, src_value, ibc.imm, rot, pre_fprc, post_fprc);
    }
#endif
}
```

**3) Witness extraction (trace_fp.cpp)**
```cpp
std::string witness_json(
    uint64_t pre_dst_bits,
    uint64_t pre_src_bits,
    uint64_t post_dst_bits,
    uint32_t fprc,
    bool is_add_sub,
    bool is_mul,
    bool is_div,
    bool is_sqrt
) {
    FloatParts a = unpack_fp(pre_dst_bits);
    FloatParts b = unpack_fp(pre_src_bits);
    FloatParts r = unpack_fp(post_dst_bits);
    uint16_t alignment_shift = 0;
    if (is_add_sub) {
        alignment_shift = (a.exponent > b.exponent) ? static_cast<uint16_t>(a.exponent - b.exponent) : static_cast<uint16_t>(b.exponent - a.exponent);
    }

    unsigned __int128 extended = 0;
    uint64_t ext_hi = 0;
    uint64_t ext_lo = 0;
    uint8_t grs = 0;
    uint8_t normalization_shift = 0;

    // FADD/FSUB
    if (is_add_sub) {
        uint16_t shift = alignment_shift > 63 ? 63 : alignment_shift;
        uint64_t mant_a = a.mantissa;
        uint64_t mant_b = b.mantissa;
        if (a.exponent < b.exponent) {
            std::swap(mant_a, mant_b);
        }
        unsigned __int128 shifted_b = mant_b;
        if (shift > 0) {
            shifted_b = static_cast<unsigned __int128>(mant_b) >> shift;
            grs = compute_grs(static_cast<unsigned __int128>(mant_b), shift);
        }
        extended = static_cast<unsigned __int128>(mant_a) + shifted_b;
    }

    // FMUL
    if (is_mul) {
        unsigned __int128 product = static_cast<unsigned __int128>(a.mantissa) * static_cast<unsigned __int128>(b.mantissa);
        extended = product;
        int msb = msb_index_u128(product);
        int shift = (msb >= 0) ? (msb - 52) : 0;
        if (shift > 0) {
            grs = compute_grs(product, shift);
        }
    }

    // FDIV (fixed-point long division)
    if (is_div) {
        int shift = 128 - num_bits_u64(a.mantissa);
        uint8_t div_grs = 0;
        extended = div_u64_to_u128(a.mantissa, b.mantissa, shift, div_grs);
        grs = div_grs;
    }

    ext_hi = static_cast<uint64_t>(extended >> 64);
    ext_lo = static_cast<uint64_t>(extended & 0xFFFFFFFFFFFFFFFFULL);

    std::ostringstream oss;
    oss << "{"
        << "\"mantissa_a\":\"" << hex_u64(a.mantissa) << "\","
        << "\"mantissa_b\":\"" << hex_u64(b.mantissa) << "\","
        << "\"alignment_shift\":" << alignment_shift << ","
        << "\"extended_mantissa_hi\":\"" << hex_u64(ext_hi) << "\","
        << "\"extended_mantissa_lo\":\"" << hex_u64(ext_lo) << "\","
        << "\"grs\":\"0b" << ((grs >> 2) & 1) << ((grs >> 1) & 1) << (grs & 1) << "\","
        << "\"result_exponent\":" << r.exponent << ","
        << "\"fprc_at_execution\":" << fprc
        << "}";
    return oss.str();
}
```

### MoneroVM Test Vector Pipeline
Location: this repo

- **Trace→Cairo generator**: `tools/generate_fp_vectors.py`
- **Full pipeline runner**: `tools/run_fp_vector_pipeline.sh`
- **Per‑opcode split**: `tools/split_fp_trace.py` (JSONL per opcode)
- **Index summary**: `tools/summarize_fp_vectors.py` → `test_vectors/INDEX.md`
- **Generated vectors (on demand)**: `tests/test_fp_vectors.cairo`

#### Code Snippets (Pipeline)

**1) Pipeline runner (tools/run_fp_vector_pipeline.sh)**
```bash
cmake -S ${RANDOMX_DIR:-../RandomX} -B ${RANDOMX_DIR:-../RandomX}/build-trace -DRANDOMX_TRACE_FP=ON -DCMAKE_BUILD_TYPE=Release
cmake --build ${RANDOMX_DIR:-../RandomX}/build-trace --target randomx-fp-trace -j

${RANDOMX_DIR:-../RandomX}/build-trace/randomx-fp-trace --out tools/fp_trace.jsonl

python3 tools/generate_fp_vectors.py --trace tools/fp_trace.jsonl --out tests/test_fp_vectors.cairo
python3 tools/split_fp_trace.py --trace tools/fp_trace.jsonl --out-dir test_vectors
python3 tools/summarize_fp_vectors.py --dir test_vectors --out test_vectors/INDEX.md
```

**2) Trace → Cairo vector mapping (tools/generate_fp_vectors.py)**
```python
if opcode in ("FADD_R", "FSUB_R", "FMUL_R", "FDIV_M"):
    vectors[key].append(
        {
            "a": pre_dst,
            "b": pre_src,
            "result": post_dst,
            "rounding_mode": fprc,
            "witness": witness,
        }
    )
```

**3) Per‑opcode split (tools/split_fp_trace.py)**
```python
if opcode not in handles:
    out_path = out_dir / f"fp_vectors_{opcode}.jsonl"
    handles[opcode] = out_path.open("w", encoding="utf-8")
handles[opcode].write(json.dumps(rec, separators=(",", ":")) + "\n")
```

### Spec Fix

- `FSCAL_R` verifier now correctly targets **F‑group (f0–f3)**
  - `src/randomx/fraud_proof.cairo`
  - Updated tests in `tests/test_fraud_proof.cairo`

#### Code Snippet (FSCAL_R verifier fix)
```cairo
pub fn verify_fscal_r_stub(dst_idx: u8) -> bool {
    // FSCAL_R operates on F-group (f0-f3, indices 0-3)
    dst_idx < 4
}

pub fn verify_fscal_r(
    pre_value_low: u64,
    pre_value_high: u64,
    post_value_low: u64,
    post_value_high: u64,
    dst_idx: u8
) -> bool {
    if dst_idx >= 4 {
        return false;
    }
    let expected_low = pre_value_low ^ FSCAL_MASK;
    let expected_high = pre_value_high ^ FSCAL_MASK;
    post_value_low == expected_low && post_value_high == expected_high
}
```

### FTZ/DAZ Replication (MXCSR 0x9FC0)

- Denormals flush to signed zero in verifier (matches RandomX FTZ/DAZ)
  - `src/randomx/fraud_proof.cairo`
- Witness explicitly records `ftz_daz_active = 1`
  - `tools/generate_fp_vectors.py`
  - `${RANDOMX_DIR:-../RandomX}/src/trace_fp.cpp`

#### Code Snippet (FTZ/DAZ flush + witness flag)
```cairo
pub fn apply_ftz_daz_bits(bits: u64) -> u64 {
    let exp_bits = bits & EXPONENT_MASK;
    let mant_bits = bits & MANTISSA_MASK;
    if exp_bits == 0 && mant_bits != 0 {
        return bits & SIGN_MASK;
    }
    bits
}
```

### Optional Cross‑Validation

- Script added to build/run SChernykh OpenCL tests:
  - `tools/run_opencl_validation.sh`
  - Requires GPU + OpenCL + `clrxasm` (CLRadeonExtender)

## How to Reproduce (Auditor)

1) Generate trace + vectors:
```
tools/run_fp_vector_pipeline.sh
```

2) Inspect per‑opcode JSONL files:
```
ls test_vectors/fp_vectors_*.jsonl
cat test_vectors/INDEX.md
```

3) (Optional) OpenCL validation:
```
tools/run_opencl_validation.sh
```

## Trace/Witness Coverage Notes

- **FADD/FSUB/FMUL**: mantissa, exponent, sign, alignment shift, extended mantissa, and GRS bits are emitted.
- **FDIV**: extended mantissa + GRS produced via fixed‑point long division.
- **FSQRT**: extended mantissa derived from result mantissa (GRS = 0). Full sqrt witness can be added later if required.

## Key Questions for Audit Review

### 1) Trace Semantics & Completeness
- Are the trace fields sufficient for on‑chain verification, or do you require additional intermediate values?
- For **FDIV** and **FSQRT**, do you require full witness derivation (exact rounding proof), or is current coverage adequate for now?

### 2) Witness Structure Validation
- Does the current FPWitness shape match what you expect for provable FP correctness?
- Should we add explicit `fprc_at_execution` to the witness fields for all ops (even when inferred from trace order)?

### 3) Rounding Mode Handling
- Are the GRS + rounding_adjustment checks adequate? If not, please specify the exact rounding decision logic to enforce.
- Should we add explicit checks for signed zero propagation under non‑ties‑to‑even modes?
  - Implemented signed-zero test coverage and vectors; full tie-break verification still pending.

### 4) E‑Group / F‑Group Constraints
- Confirm the updated **FSCAL_R F‑group** fix is correct.
- Any other register‑group constraints you want enforced explicitly in the verifier?

### 5) Verification Strategy / Gas Targets
- Are current gas targets acceptable with witness verification?
- Any specific instructions to prioritize for optimization beyond FMUL/FADD?

### 6) Cross‑Validation Strategy
- Is SChernykh OpenCL sufficient as a second reference, or do you want another reference implementation (e.g., tests.cpp vectors only)?

## Requested Next‑Step Guidance

- Should we proceed to **full FDIV/FSQRT witness** (exact rounding verification), or defer?
- Do you want a **minimal auditor‑approved vector set** (P0 only) before widening coverage?
- Any specific invariants or checks you want encoded before M2 sign‑off?

---

If you want a shorter summary email or a checklist‑style audit plan, I can provide that as well.
