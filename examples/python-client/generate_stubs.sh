#!/usr/bin/env bash
# generate_stubs.sh — Generate Python gRPC stubs from Misogi V1 proto definition.
#
# Usage:
#   bash generate_stubs.sh
#
# Prerequisites:
#   - Python 3.11+ with grpcio-tools installed
#   - Proto file at ../../proto-dist/v1/misogi.proto

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROTO_ROOT="${SCRIPT_DIR}/../../proto-dist/v1"
PROTO_FILE="misogi.proto"
OUTPUT_DIR="${SCRIPT_DIR}/src/misogi_client/pb2"

echo "==> Misogi Python gRPC Stub Generator"
echo "    Proto source : ${PROTO_ROOT}/${PROTO_FILE}"
echo "    Output target: ${OUTPUT_DIR}"
echo ""

if [ ! -f "${PROTO_ROOT}/${PROTO_FILE}" ]; then
    echo "[ERROR] Proto file not found: ${PROTO_ROOT}/${PROTO_FILE}" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

python -m grpc_tools.protoc \
    -I"${PROTO_ROOT}" \
    --python_out="${OUTPUT_DIR}" \
    --grpc_python_out="${OUTPUT_DIR}" \
    "${PROTO_ROOT}/${PROTO_FILE}"

echo ""
echo "[OK] Stubs generated successfully in ${OUTPUT_DIR}/"
echo "     - misogi_pb2.py          (message types)"
echo "     - misogi_pb2_grpc.py     (service stubs)"
