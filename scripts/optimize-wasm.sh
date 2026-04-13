#!/usr/bin/env bash
# optimize-wasm.sh — Optimize WASM binary using Binaryen's wasm-opt for production deployment.
#
# Usage:
#   ./scripts/optimize-wasm.sh <input.wasm> [output.wasm]
#
# Prerequisites:
#   - wasm-opt from Binaryen (https://github.com/WebAssembly/binaryen)
#
# Exit codes:
#   0 - Success
#   1 - Input file not found
#   2 - wasm-opt not found
#   3 - Optimization failed
#   4 - Size check failed (output exceeds budget)

set -euo pipefail

# ===========================================================================
# Configuration
# ===========================================================================

BUDGET_RAW_MB=8
BUDGET_GZIP_MB=3

INPUT="${1:?Usage: optimize-wasm.sh <input.wasm> [output.wasm]}"
OUTPUT="${2:-${INPUT%.wasm}.opt.wasm}"

echo "=== Misogi WASM Optimizer ==="
echo ""

# ===========================================================================
# Validation
# ===========================================================================

if [[ ! -f "$INPUT" ]]; then
    echo "[ERROR] Input file not found: $INPUT" >&2
    exit 1
fi

if ! command -v wasm-opt &>/dev/null; then
    echo "[ERROR] wasm-opt not found. Install Binaryen:" >&2
    echo "        https://github.com/WebAssembly/binaryen/releases" >&2
    exit 2
fi

# ===========================================================================
# File Size Detection (Cross-Platform: GNU stat / BSD stat / Git Bash)
# ===========================================================================

get_file_size() {
    local file="$1"
    if command -v stat &>/dev/null; then
        # Try GNU stat first (Linux)
        local size
        size=$(stat -c%s "$file" 2>/dev/null) || size=$(stat -f%z "$file" 2>/dev/null) || {
            # Fallback for Git Bash on Windows (wc -c)
            size=$(wc -c < "$file" | tr -d ' ')
        }
        echo "$size"
    else
        wc -c < "$file" | tr -d ' '
    fi
}

ORIGINAL_SIZE=$(get_file_size "$INPUT")
ORIGINAL_MB=$(awk "BEGIN {printf \"%.2f\", ${ORIGINAL_SIZE} / 1048576}")
echo "Input:  $INPUT (${ORIGINAL_MB} MB)"

# ===========================================================================
# Optimization Phase
# ===========================================================================

echo ""
echo "--> Running wasm-opt -Oz ..."

if ! wasm-opt -Oz \
    --remove-name-section \
    --remove-dwarf \
    -o "$OUTPUT" \
    "$INPUT"; then
    echo "[ERROR] Optimization failed" >&2
    exit 3
fi

OPTIMIZED_SIZE=$(get_file_size "$OUTPUT")
SAVED_BYTES=$(( ORIGINAL_SIZE - OPTIMIZED_SIZE ))
SAVED_PCT=$(( SAVED_BYTES * 100 / ORIGINAL_SIZE ))
OPTIMIZED_MB=$(awk "BEGIN {printf \"%.2f\", ${OPTIMIZED_SIZE} / 1048576}")
echo "Output: $OUTPUT (${OPTIMIZED_MB} MB, -$SAVED_PCT%)"

# ===========================================================================
# Gzip Size Check
# ===========================================================================

GZIP_SIZE=$(gzip -c "$OUTPUT" | wc -c | tr -d ' ')
GZIP_MB=$(awk "BEGIN {printf \"%.2f\", ${GZIP_SIZE} / 1048576}")
echo "Gzip:   ${GZIP_MB} MB"

# ===========================================================================
# Budget Validation
# ===========================================================================

BUDGET_RAW_BYTES=$(( BUDGET_RAW_MB * 1024 * 1024 ))
BUDGET_GZIP_BYTES=$(( BUDGET_GZIP_MB * 1024 * 1024 ))

FAILED=0

echo ""
echo "--- Budget Check ---"

if (( OPTIMIZED_SIZE > BUDGET_RAW_BYTES )); then
    echo "[FAIL] Raw size ${OPTIMIZED_SIZE} bytes exceeds budget ${BUDGET_RAW_BYTES} bytes (${BUDGET_RAW_MB}MB)" >&2
    FAILED=1
else
    echo "[PASS] Raw size within ${BUDGET_RAW_MB}MB budget (${OPTIMIZED_SIZE}/${BUDGET_RAW_BYTES} bytes)"
fi

if (( GZIP_SIZE > BUDGET_GZIP_BYTES )); then
    echo "[FAIL] Gzip size ${GZIP_SIZE} bytes exceeds budget ${BUDGET_GZIP_BYTES} bytes (${BUDGET_GZIP_MB}MB)" >&2
    FAILED=1
else
    echo "[PASS] Gzip size within ${BUDGET_GZIP_MB}MB budget (${GZIP_SIZE}/${BUDGET_GZIP_BYTES} bytes)"
fi

# ===========================================================================
# Summary
# ===========================================================================

echo ""
if [[ $FAILED -eq 0 ]]; then
    echo "=== Optimization Complete ==="
else
    echo "=== Optimization Failed (Budget Exceeded) ===" >&2
fi

exit $FAILED
