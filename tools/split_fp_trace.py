#!/usr/bin/env python3
"""Split fp_trace.jsonl into per-opcode JSONL files.

Usage:
  python tools/split_fp_trace.py --trace tools/fp_trace.jsonl --out-dir test_vectors
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, TextIO


def main() -> None:
    parser = argparse.ArgumentParser(description="Split FP trace JSONL by opcode.")
    parser.add_argument("--trace", type=Path, required=True, help="Path to fp_trace.jsonl")
    parser.add_argument("--out-dir", type=Path, required=True, help="Output directory")
    args = parser.parse_args()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    handles: Dict[str, TextIO] = {}

    with args.trace.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("type") != "fp_op":
                continue
            opcode = rec.get("opcode", "unknown").lower()
            if opcode not in handles:
                out_path = out_dir / f"fp_vectors_{opcode}.jsonl"
                handles[opcode] = out_path.open("w", encoding="utf-8")
            handles[opcode].write(json.dumps(rec, separators=(",", ":")) + "\n")

    for handle in handles.values():
        handle.close()

    print(f"Wrote {len(handles)} opcode files to {out_dir}")


if __name__ == "__main__":
    main()
