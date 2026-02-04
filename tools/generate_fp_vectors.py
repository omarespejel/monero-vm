#!/usr/bin/env python3
"""Generate Cairo FP test vectors from JSONL traces or defaults.

Usage:
  python tools/generate_fp_vectors.py \
    --out tests/test_fp_vectors.cairo \
    --trace /path/to/fp_trace.jsonl

If --trace is omitted, a small built-in set of sanity vectors is used.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_VECTORS: Dict[str, List[Dict[str, Any]]] = {
    "fadd": [
        {"a": 0x3FF0000000000000, "b": 0x3FF0000000000000, "result": 0x4000000000000000, "rounding_mode": 0},
        {"a": 0x0000000000000000, "b": 0x3FF0000000000000, "result": 0x3FF0000000000000, "rounding_mode": 0},
        {"a": 0x7FF0000000000000, "b": 0x3FF0000000000000, "result": 0x7FF0000000000000, "rounding_mode": 0},
        {"a": 0x7FF0000000000000, "b": 0xFFF0000000000000, "result": 0x7FF8000000000000, "rounding_mode": 0},
    ],
    "fsub": [
        {"a": 0x3FF0000000000000, "b": 0x3FF0000000000000, "result": 0x0000000000000000, "rounding_mode": 0},
        {"a": 0x0000000000000000, "b": 0x3FF0000000000000, "result": 0xBFF0000000000000, "rounding_mode": 0},
    ],
    "fmul": [
        {"a": 0x4000000000000000, "b": 0x4000000000000000, "result": 0x4010000000000000, "rounding_mode": 0},
        {"a": 0x0000000000000000, "b": 0x7FF0000000000000, "result": 0x7FF8000000000000, "rounding_mode": 0},
        {"a": 0xC000000000000000, "b": 0x4000000000000000, "result": 0xC010000000000000, "rounding_mode": 0},
    ],
    "fdiv": [
        {"a": 0x4010000000000000, "b": 0x4000000000000000, "result": 0x4000000000000000, "rounding_mode": 0},
        {"a": 0x0000000000000000, "b": 0x0000000000000000, "result": 0x7FF8000000000000, "rounding_mode": 0},
        {"a": 0x3FF0000000000000, "b": 0x0000000000000000, "result": 0x7FF0000000000000, "rounding_mode": 0},
    ],
    "fscal": [
        {
            "dst_idx": 0,
            "pre_lo": 0x3FF0000000000000,
            "pre_hi": 0x4000000000000000,
            "post_lo": 0xBF00000000000000,
            "post_hi": 0xC0F0000000000000,
        }
    ],
    "fsqrt": [
        {"a": 0x4010000000000000, "result": 0x4000000000000000, "rounding_mode": 0},
        {"a": 0xBFF0000000000000, "result": 0x7FF8000000000000, "rounding_mode": 0},
        {"a": 0x0000000000000000, "result": 0x0000000000000000, "rounding_mode": 0},
    ],
    "fadd_m": [
        {
            "dst_lo": 0x3FF0000000000000,
            "dst_hi": 0x4000000000000000,
            "mem": 0x0000000100000002,
            "post_lo": 0x4008000000000000,
            "post_hi": 0x4008000000000000,
            "rounding_mode": 0,
        }
    ],
    "fsub_m": [
        {
            "dst_lo": 0x4000000000000000,
            "dst_hi": 0x4000000000000000,
            "mem": 0xFFFFFFFF00000001,
            "post_lo": 0x3FF0000000000000,
            "post_hi": 0x4008000000000000,
            "rounding_mode": 0,
        }
    ],
}


def _parse_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        if value.startswith("0x") or value.startswith("0X"):
            return int(value, 16)
        return int(value)
    raise TypeError(f"Unsupported int value: {value!r}")


def _parse_grs(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if value.startswith("0b"):
            return int(value[2:], 2)
    return _parse_int(value)


def _normalize_witness(witness: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not witness:
        return None
    fields = {
        "extended_mantissa_hi": 0,
        "extended_mantissa_lo": 0,
        "rounding_adjustment": 0,
        "guard_round_sticky": 0,
        "result_exponent": 0,
        "normalization_shift": 0,
        "alignment_shift": 0,
        "sign_a": 0,
        "sign_b": 0,
        "sign_result": 0,
        "ftz_daz_active": 1,
        "fprc_at_execution": 0,
        "is_sub": 0,
    }
    if "extended_mantissa_hi" in witness:
        fields["extended_mantissa_hi"] = _parse_int(witness["extended_mantissa_hi"])
    if "extended_mantissa_lo" in witness:
        fields["extended_mantissa_lo"] = _parse_int(witness["extended_mantissa_lo"])
    if "rounding_adjustment" in witness:
        fields["rounding_adjustment"] = int(witness["rounding_adjustment"])
    grs = witness.get("guard_round_sticky", witness.get("grs"))
    if grs is not None:
        fields["guard_round_sticky"] = int(_parse_grs(grs))
    if "result_exponent" in witness:
        fields["result_exponent"] = int(witness["result_exponent"])
    if "normalization_shift" in witness:
        fields["normalization_shift"] = int(witness["normalization_shift"])
    if "alignment_shift" in witness:
        fields["alignment_shift"] = int(witness["alignment_shift"])
    if "sign_a" in witness:
        fields["sign_a"] = int(witness["sign_a"])
    if "sign_b" in witness:
        fields["sign_b"] = int(witness["sign_b"])
    if "sign_result" in witness:
        fields["sign_result"] = int(witness["sign_result"])
    if "ftz_daz_active" in witness:
        fields["ftz_daz_active"] = int(witness["ftz_daz_active"])
    if "fprc_at_execution" in witness:
        fields["fprc_at_execution"] = int(witness["fprc_at_execution"])
    if "is_sub" in witness:
        fields["is_sub"] = int(witness["is_sub"])
    return fields


def _parse_reg_idx(name: Optional[str]) -> Optional[int]:
    if not name:
        return None
    name = name.strip().lower()
    if len(name) < 2:
        return None
    prefix = name[0]
    try:
        idx = int(name[1:])
    except ValueError:
        return None
    if prefix == "f":
        return idx
    if prefix == "e":
        return 4 + idx
    return idx


def load_trace(path: Path) -> Dict[str, List[Dict[str, Any]]]:
    vectors: Dict[str, List[Dict[str, Any]]] = {
        "fadd": [],
        "fsub": [],
        "fmul": [],
        "fdiv": [],
        "fsqrt": [],
        "fadd_m": [],
        "fsub_m": [],
        "fscal": [],
    }

    mem_pairs: Dict[tuple, Dict[str, Any]] = {}
    fscal_pairs: Dict[tuple, Dict[str, Any]] = {}

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("type") != "fp_op":
                continue
            opcode = rec.get("opcode", "").upper()
            lane = int(rec.get("lane", 0))
            fprc = int(rec.get("fprc", 0))
            pre_dst = _parse_int(rec["pre_dst"])
            pre_src = _parse_int(rec.get("pre_src", 0))
            post_dst = _parse_int(rec["post_dst"])
            witness = _normalize_witness(rec.get("witness"))

            if opcode in ("FADD_R", "FSUB_R", "FMUL_R", "FDIV_M"):
                key = {
                    "FADD_R": "fadd",
                    "FSUB_R": "fsub",
                    "FMUL_R": "fmul",
                    "FDIV_M": "fdiv",
                }[opcode]
                vectors[key].append(
                    {
                        "a": pre_dst,
                        "b": pre_src,
                        "result": post_dst,
                        "rounding_mode": fprc,
                        "witness": witness,
                    }
                )
                continue

            if opcode == "FSQRT_R":
                vectors["fsqrt"].append(
                    {
                        "a": pre_dst,
                        "result": post_dst,
                        "rounding_mode": fprc,
                        "witness": witness,
                    }
                )
                continue

            if opcode in ("FADD_M", "FSUB_M"):
                mem_raw = _parse_int(rec.get("mem_raw", 0))
                dst_reg = rec.get("dst_reg")
                src_reg = rec.get("src_reg")
                key = (opcode, rec.get("pc"), dst_reg, src_reg, fprc, mem_raw)
                entry = mem_pairs.setdefault(
                    key,
                    {
                        "dst_lo": None,
                        "dst_hi": None,
                        "post_lo": None,
                        "post_hi": None,
                        "mem": mem_raw,
                        "rounding_mode": fprc,
                        "witness_lo": None,
                        "witness_hi": None,
                    },
                )
                if lane == 0:
                    entry["dst_lo"] = pre_dst
                    entry["post_lo"] = post_dst
                    entry["witness_lo"] = witness
                else:
                    entry["dst_hi"] = pre_dst
                    entry["post_hi"] = post_dst
                    entry["witness_hi"] = witness

                if entry["dst_lo"] is not None and entry["dst_hi"] is not None:
                    vectors["fadd_m" if opcode == "FADD_M" else "fsub_m"].append(entry)
                    mem_pairs.pop(key, None)
                continue

            if opcode == "FSCAL_R":
                dst_reg = rec.get("dst_reg")
                dst_idx = _parse_reg_idx(dst_reg)
                key = (opcode, rec.get("pc"), dst_reg, fprc)
                entry = fscal_pairs.setdefault(
                    key,
                    {
                        "dst_idx": dst_idx if dst_idx is not None else 0,
                        "pre_lo": None,
                        "pre_hi": None,
                        "post_lo": None,
                        "post_hi": None,
                    },
                )
                if lane == 0:
                    entry["pre_lo"] = pre_dst
                    entry["post_lo"] = post_dst
                else:
                    entry["pre_hi"] = pre_dst
                    entry["post_hi"] = post_dst

                if entry["pre_lo"] is not None and entry["pre_hi"] is not None:
                    vectors["fscal"].append(entry)
                    fscal_pairs.pop(key, None)
                continue

    _add_ftz_daz_vectors(vectors)
    _add_rounding_edge_vectors(vectors)
    _add_fdiv_boundary_vectors(vectors)
    return vectors


def _add_ftz_daz_vectors(vectors: Dict[str, List[Dict[str, Any]]]) -> None:
    denorm = 0x0000000000000001
    one = 0x3FF0000000000000
    zero = 0x0000000000000000
    inf = 0x7FF0000000000000

    vectors["fadd"].append(
        {
            "a": denorm,
            "b": one,
            "result": one,
            "rounding_mode": 0,
            "witness": None,
        }
    )
    vectors["fsub"].append(
        {
            "a": one,
            "b": denorm,
            "result": one,
            "rounding_mode": 0,
            "witness": None,
        }
    )
    vectors["fmul"].append(
        {
            "a": denorm,
            "b": one,
            "result": zero,
            "rounding_mode": 0,
            "witness": None,
        }
    )
    vectors["fdiv"].append(
        {
            "a": one,
            "b": denorm,
            "result": inf,
            "rounding_mode": 0,
            "witness": None,
        }
    )
    vectors["fsqrt"].append(
        {
            "a": denorm,
            "result": zero,
            "rounding_mode": 0,
            "witness": None,
        }
    )


def _add_rounding_edge_vectors(vectors: Dict[str, List[Dict[str, Any]]]) -> None:
    pos_zero = 0x0000000000000000
    neg_zero = 0x8000000000000000

    vectors["fadd"].append(
        {
            "a": pos_zero,
            "b": neg_zero,
            "result": neg_zero,
            "rounding_mode": 1,
            "witness": None,
        }
    )
    vectors["fadd"].append(
        {
            "a": pos_zero,
            "b": neg_zero,
            "result": pos_zero,
            "rounding_mode": 0,
            "witness": None,
        }
    )
    vectors["fsub"].append(
        {
            "a": pos_zero,
            "b": pos_zero,
            "result": neg_zero,
            "rounding_mode": 1,
            "witness": None,
        }
    )


def _add_fdiv_boundary_vectors(vectors: Dict[str, List[Dict[str, Any]]]) -> None:
    # E-group min divisor boundary per auditor recommendation.
    min_divisor = 0x3000000000000001
    max_finite = 0x7FEFFFFFFFFFFFFF
    one = 0x3FF0000000000000
    inf = 0x7FF0000000000000

    vectors["fdiv"].append(
        {
            "a": max_finite,
            "b": min_divisor,
            "result": inf,
            "rounding_mode": 0,
            "witness": None,
        }
    )
    vectors["fdiv"].append(
        {
            "a": one,
            "b": min_divisor,
            "result": inf,
            "rounding_mode": 0,
            "witness": None,
        }
    )


def format_hex(value: int) -> str:
    return f"0x{value:016X}"


def render_witness(witness: Optional[Dict[str, Any]], indent: str = "        ") -> str:
    if not witness:
        return f"{indent}default_fp_witness()"
    fields = {
        "extended_mantissa_hi": 0,
        "extended_mantissa_lo": 0,
        "rounding_adjustment": 0,
        "guard_round_sticky": 0,
        "result_exponent": 0,
        "normalization_shift": 0,
        "alignment_shift": 0,
        "sign_a": 0,
        "sign_b": 0,
        "sign_result": 0,
        "ftz_daz_active": 1,
        "fprc_at_execution": 0,
        "is_sub": 0,
    }
    fields.update(witness)
    return (
        f"{indent}FPWitness {{\n"
        f"{indent}    extended_mantissa_hi: {format_hex(_parse_int(fields['extended_mantissa_hi']))},\n"
        f"{indent}    extended_mantissa_lo: {format_hex(_parse_int(fields['extended_mantissa_lo']))},\n"
        f"{indent}    rounding_adjustment: {int(fields['rounding_adjustment'])},\n"
        f"{indent}    guard_round_sticky: {int(fields['guard_round_sticky'])},\n"
        f"{indent}    result_exponent: {int(fields['result_exponent'])},\n"
        f"{indent}    normalization_shift: {int(fields['normalization_shift'])},\n"
        f"{indent}    alignment_shift: {int(fields['alignment_shift'])},\n"
        f"{indent}    sign_a: {int(fields['sign_a'])},\n"
        f"{indent}    sign_b: {int(fields['sign_b'])},\n"
        f"{indent}    sign_result: {int(fields['sign_result'])},\n"
        f"{indent}    ftz_daz_active: {int(fields['ftz_daz_active'])},\n"
        f"{indent}    fprc_at_execution: {int(fields['fprc_at_execution'])},\n"
        f"{indent}    is_sub: {int(fields['is_sub'])},\n"
        f"{indent}}}"
    )


def render_vectors(vectors: Dict[str, List[Dict[str, Any]]]) -> str:
    def render_bin_vec_list(name: str) -> str:
        items = []
        for v in vectors[name]:
            witness = render_witness(v.get("witness"))
            items.append(
                "        FPBinVector {\n"
                f"            a: {format_hex(_parse_int(v['a']))},\n"
                f"            b: {format_hex(_parse_int(v['b']))},\n"
                f"            result: {format_hex(_parse_int(v['result']))},\n"
                f"            rounding_mode: {int(v.get('rounding_mode', 0))},\n"
                f"            witness: {witness.strip()},\n"
                "        },"
            )
        if not items:
            return "        // (no vectors loaded)\n"
        return "\n".join(items) + "\n"

    def render_sqrt_vec_list() -> str:
        items = []
        for v in vectors["fsqrt"]:
            witness = render_witness(v.get("witness"))
            items.append(
                "        FPSqrtVector {\n"
                f"            a: {format_hex(_parse_int(v['a']))},\n"
                f"            result: {format_hex(_parse_int(v['result']))},\n"
                f"            rounding_mode: {int(v.get('rounding_mode', 0))},\n"
                f"            witness: {witness.strip()},\n"
                "        },"
            )
        if not items:
            return "        // (no vectors loaded)\n"
        return "\n".join(items) + "\n"

    def render_fscal_vec_list() -> str:
        items = []
        for v in vectors["fscal"]:
            items.append(
                "        FPFscalVector {\n"
                f"            dst_idx: {int(v.get('dst_idx', 0))},\n"
                f"            pre_lo: {format_hex(_parse_int(v['pre_lo']))},\n"
                f"            pre_hi: {format_hex(_parse_int(v['pre_hi']))},\n"
                f"            post_lo: {format_hex(_parse_int(v['post_lo']))},\n"
                f"            post_hi: {format_hex(_parse_int(v['post_hi']))},\n"
                "        },"
            )
        if not items:
            return "        // (no vectors loaded)\n"
        return "\n".join(items) + "\n"

    def render_mem_vec_list(name: str) -> str:
        items = []
        for v in vectors[name]:
            witness_lo = render_witness(v.get("witness_lo"))
            witness_hi = render_witness(v.get("witness_hi"))
            items.append(
                "        FPMemVector {\n"
                f"            dst_lo: {format_hex(_parse_int(v['dst_lo']))},\n"
                f"            dst_hi: {format_hex(_parse_int(v['dst_hi']))},\n"
                f"            mem: {format_hex(_parse_int(v['mem']))},\n"
                f"            post_lo: {format_hex(_parse_int(v['post_lo']))},\n"
                f"            post_hi: {format_hex(_parse_int(v['post_hi']))},\n"
                f"            rounding_mode: {int(v.get('rounding_mode', 0))},\n"
                f"            witness_lo: {witness_lo.strip()},\n"
                f"            witness_hi: {witness_hi.strip()},\n"
                "        },"
            )
        if not items:
            return "        // (no vectors loaded)\n"
        return "\n".join(items) + "\n"

    return {
        "fadd": render_bin_vec_list("fadd"),
        "fsub": render_bin_vec_list("fsub"),
        "fmul": render_bin_vec_list("fmul"),
        "fdiv": render_bin_vec_list("fdiv"),
        "fsqrt": render_sqrt_vec_list(),
        "fadd_m": render_mem_vec_list("fadd_m"),
        "fsub_m": render_mem_vec_list("fsub_m"),
        "fscal": render_fscal_vec_list(),
    }


def generate_file(vectors: Dict[str, List[Dict[str, Any]]], out_path: Path) -> None:
    rendered = render_vectors(vectors)
    template = """// AUTO-GENERATED: tools/generate_fp_vectors.py
// DO NOT EDIT BY HAND

use monero_vm::randomx::fraud_proof::ieee754::{
    FPWitness, default_fp_witness,
    verify_fadd_with_witness, verify_fmul_with_witness,
    verify_fdiv_with_witness, verify_fsqrt_with_witness,
    verify_fadd_m, verify_fsub_m,
    verify_fscal_r,
    ROUND_TIES_TO_EVEN, ROUND_TOWARD_NEGATIVE, ROUND_TOWARD_POSITIVE, ROUND_TOWARD_ZERO,
    SIGN_MASK
};

#[derive(Drop, Copy, Serde)]
struct FPBinVector {
    a: u64,
    b: u64,
    result: u64,
    rounding_mode: u8,
    witness: FPWitness,
}

#[derive(Drop, Copy, Serde)]
struct FPSqrtVector {
    a: u64,
    result: u64,
    rounding_mode: u8,
    witness: FPWitness,
}

#[derive(Drop, Copy, Serde)]
struct FPMemVector {
    dst_lo: u64,
    dst_hi: u64,
    mem: u64,
    post_lo: u64,
    post_hi: u64,
    rounding_mode: u8,
    witness_lo: FPWitness,
    witness_hi: FPWitness,
}

#[derive(Drop, Copy, Serde)]
struct FPFscalVector {
    dst_idx: u8,
    pre_lo: u64,
    pre_hi: u64,
    post_lo: u64,
    post_hi: u64,
}

fn fadd_vectors() -> Array<FPBinVector> {
    array![
__FADD__    ]
}

fn fsub_vectors() -> Array<FPBinVector> {
    array![
__FSUB__    ]
}

fn fmul_vectors() -> Array<FPBinVector> {
    array![
__FMUL__    ]
}

fn fdiv_vectors() -> Array<FPBinVector> {
    array![
__FDIV__    ]
}

fn fsqrt_vectors() -> Array<FPSqrtVector> {
    array![
__FSQRT__    ]
}

fn fadd_m_vectors() -> Array<FPMemVector> {
    array![
__FADD_M__    ]
}

fn fsub_m_vectors() -> Array<FPMemVector> {
    array![
__FSUB_M__    ]
}

fn fscal_vectors() -> Array<FPFscalVector> {
    array![
__FSCAL__    ]
}

#[test]
fn test_fp_vectors_fadd() {
    let vectors = fadd_vectors();
    let mut i: u32 = 0;
    loop {
        if i >= vectors.len() {
            break;
        }
        let v = *vectors.at(i);
        assert(
            verify_fadd_with_witness(v.a, v.b, v.result, v.rounding_mode, v.witness),
            'fadd vector failed'
        );
        i += 1;
    };
}

#[test]
fn test_fp_vectors_fsub() {
    let vectors = fsub_vectors();
    let mut i: u32 = 0;
    loop {
        if i >= vectors.len() {
            break;
        }
        let v = *vectors.at(i);
        let neg_b = v.b ^ SIGN_MASK;
        assert(
            verify_fadd_with_witness(v.a, neg_b, v.result, v.rounding_mode, v.witness),
            'fsub vector failed'
        );
        i += 1;
    };
}

#[test]
fn test_fp_vectors_fmul() {
    let vectors = fmul_vectors();
    let mut i: u32 = 0;
    loop {
        if i >= vectors.len() {
            break;
        }
        let v = *vectors.at(i);
        assert(
            verify_fmul_with_witness(v.a, v.b, v.result, v.rounding_mode, v.witness),
            'fmul vector failed'
        );
        i += 1;
    };
}

#[test]
fn test_fp_vectors_fdiv() {
    let vectors = fdiv_vectors();
    let mut i: u32 = 0;
    loop {
        if i >= vectors.len() {
            break;
        }
        let v = *vectors.at(i);
        assert(
            verify_fdiv_with_witness(v.a, v.b, v.result, v.rounding_mode, v.witness),
            'fdiv vector failed'
        );
        i += 1;
    };
}

#[test]
fn test_fp_vectors_fsqrt() {
    let vectors = fsqrt_vectors();
    let mut i: u32 = 0;
    loop {
        if i >= vectors.len() {
            break;
        }
        let v = *vectors.at(i);
        assert(
            verify_fsqrt_with_witness(v.a, v.result, v.rounding_mode, v.witness),
            'fsqrt vector failed'
        );
        i += 1;
    };
}

#[test]
fn test_fp_vectors_fadd_m() {
    let vectors = fadd_m_vectors();
    let mut i: u32 = 0;
    loop {
        if i >= vectors.len() {
            break;
        }
        let v = *vectors.at(i);
        assert(
            verify_fadd_m(
                v.dst_lo,
                v.dst_hi,
                v.mem,
                v.post_lo,
                v.post_hi,
                v.rounding_mode,
                v.witness_lo,
                v.witness_hi
            ),
            'fadd_m vector failed'
        );
        i += 1;
    };
}

#[test]
fn test_fp_vectors_fsub_m() {
    let vectors = fsub_m_vectors();
    let mut i: u32 = 0;
    loop {
        if i >= vectors.len() {
            break;
        }
        let v = *vectors.at(i);
        assert(
            verify_fsub_m(
                v.dst_lo,
                v.dst_hi,
                v.mem,
                v.post_lo,
                v.post_hi,
                v.rounding_mode,
                v.witness_lo,
                v.witness_hi
            ),
            'fsub_m vector failed'
        );
        i += 1;
    };
}

#[test]
fn test_fp_vectors_fscal() {
    let vectors = fscal_vectors();
    let mut i: u32 = 0;
    loop {
        if i >= vectors.len() {
            break;
        }
        let v = *vectors.at(i);
        assert(
            verify_fscal_r(v.pre_lo, v.pre_hi, v.post_lo, v.post_hi, v.dst_idx),
            'fscal vector failed'
        );
        i += 1;
    };
}
"""
    out = (
        template.replace("__FADD__", rendered["fadd"])
        .replace("__FSUB__", rendered["fsub"])
        .replace("__FMUL__", rendered["fmul"])
        .replace("__FDIV__", rendered["fdiv"])
        .replace("__FSQRT__", rendered["fsqrt"])
        .replace("__FADD_M__", rendered["fadd_m"])
        .replace("__FSUB_M__", rendered["fsub_m"])
        .replace("__FSCAL__", rendered["fscal"])
    )
    out_path.write_text(out, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Cairo FP test vectors.")
    parser.add_argument("--trace", type=Path, help="JSONL trace file")
    parser.add_argument("--out", type=Path, default=Path("tests/test_fp_vectors.cairo"), help="Output Cairo test file")
    args = parser.parse_args()

    if args.trace:
        vectors = load_trace(args.trace)
    else:
        vectors = DEFAULT_VECTORS

    generate_file(vectors, args.out)


if __name__ == "__main__":
    main()
