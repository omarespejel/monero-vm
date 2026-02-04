#!/usr/bin/env python3
"""Summarize per-opcode FP vector counts from test_vectors/*.jsonl.

Usage:
  python tools/summarize_fp_vectors.py --dir test_vectors --out test_vectors/INDEX.md
"""
from __future__ import annotations

import argparse
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize FP vector counts.")
    parser.add_argument("--dir", type=Path, required=True, help="Directory with fp_vectors_*.jsonl")
    parser.add_argument("--out", type=Path, required=True, help="Output markdown file")
    args = parser.parse_args()

    vector_dir: Path = args.dir
    files = sorted(vector_dir.glob("fp_vectors_*.jsonl"))
    lines = ["# FP Vector Index", "", "| File | Opcode | Records |", "|---|---|---|"]

    for path in files:
        opcode = path.stem.replace("fp_vectors_", "").upper()
        count = 0
        with path.open("r", encoding="utf-8") as f:
            for _ in f:
                count += 1
        rel = path.as_posix()
        lines.append(f"| `{rel}` | `{opcode}` | {count} |")

    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
