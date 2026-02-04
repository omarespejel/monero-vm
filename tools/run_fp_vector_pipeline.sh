#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RANDX_DIR="${RANDOMX_DIR:-${ROOT_DIR}/../RandomX}"
BUILD_DIR="${RANDX_DIR}/build-trace"
TRACE_PATH="${ROOT_DIR}/tools/fp_trace.jsonl"
SPLIT_DIR="${ROOT_DIR}/test_vectors"
INDEX_PATH="${SPLIT_DIR}/INDEX.md"

if [[ ! -d "${RANDX_DIR}" ]]; then
  echo "RandomX repo not found at ${RANDX_DIR}"
  echo "Set RANDOMX_DIR to your RandomX checkout, e.g.:"
  echo "  RANDOMX_DIR=/path/to/RandomX tools/run_fp_vector_pipeline.sh"
  exit 1
fi

mkdir -p "${BUILD_DIR}"

cmake -S "${RANDX_DIR}" -B "${BUILD_DIR}" -DRANDOMX_TRACE_FP=ON -DCMAKE_BUILD_TYPE=Release
cmake --build "${BUILD_DIR}" --target randomx-fp-trace -j

"${BUILD_DIR}/randomx-fp-trace" --out "${TRACE_PATH}"

python3 "${ROOT_DIR}/tools/generate_fp_vectors.py" --trace "${TRACE_PATH}" --out "${ROOT_DIR}/tests/test_fp_vectors.cairo"
python3 "${ROOT_DIR}/tools/split_fp_trace.py" --trace "${TRACE_PATH}" --out-dir "${SPLIT_DIR}"
python3 "${ROOT_DIR}/tools/summarize_fp_vectors.py" --dir "${SPLIT_DIR}" --out "${INDEX_PATH}"

echo "Trace written to ${TRACE_PATH}"
echo "Opcode vectors written to ${SPLIT_DIR}"
echo "Index written to ${INDEX_PATH}"
