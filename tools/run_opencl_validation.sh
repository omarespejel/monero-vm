#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OPENCL_DIR="${RANDOMX_OPENCL_DIR:-${ROOT_DIR}/../RandomX_OpenCL}"
RX_DIR="${OPENCL_DIR}/RandomX"
OCL_DIR="${OPENCL_DIR}/RandomX_OpenCL"

if ! command -v clrxasm >/dev/null 2>&1; then
  echo "clrxasm not found. Install CLRadeonExtender and ensure clrxasm is in PATH." >&2
  exit 1
fi

if [ ! -d "${RX_DIR}" ] || [ ! -d "${OCL_DIR}" ]; then
  echo "RandomX_OpenCL repo not found at ${OPENCL_DIR}. Set RANDOMX_OPENCL_DIR to override." >&2
  exit 1
fi

mkdir -p "${RX_DIR}/build"
cmake -S "${RX_DIR}" -B "${RX_DIR}/build" -DARCH=native -DCMAKE_BUILD_TYPE=Release
cmake --build "${RX_DIR}/build" -j

make -C "${OCL_DIR}"

if [ -x "${OCL_DIR}/opencl_test" ]; then
  echo "Running OpenCL tests (this requires a compatible GPU + OpenCL runtime)..."
  "${OCL_DIR}/opencl_test"
else
  echo "opencl_test binary not found after build." >&2
  exit 1
fi
