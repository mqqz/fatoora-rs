#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE="${ROOT_DIR}/fatoora-core/tests/fixtures/invoices/sample-simplified-invoice.xml"
OUT_DIR="${ROOT_DIR}/bench/cli/results"
OUT_FILE="${OUT_DIR}/hash_bench.md"

if ! command -v hyperfine >/dev/null 2>&1; then
  echo "hyperfine is not installed; please install it and re-run."
  exit 1
fi

OFFICIAL_CLI="${FATOORA_CLI:-}"
RS_CLI="${FATOORA_RS_CLI:-}"

if [ -z "${OFFICIAL_CLI}" ]; then
  if command -v fatoora >/dev/null 2>&1; then
    OFFICIAL_CLI="fatoora"
  else
    echo "official SDK CLI not found. Set FATOORA_CLI to its full path."
    exit 1
  fi
fi

if [ -z "${RS_CLI}" ]; then
  if [ -x "${ROOT_DIR}/target/release/fatoora-rs-cli" ]; then
    RS_CLI="${ROOT_DIR}/target/release/fatoora-rs-cli"
  elif [ -x "${ROOT_DIR}/target/debug/fatoora-rs-cli" ]; then
    RS_CLI="${ROOT_DIR}/target/debug/fatoora-rs-cli"
  elif command -v fatoora-rs-cli >/dev/null 2>&1; then
    RS_CLI="fatoora-rs-cli"
  else
    echo "fatoora-rs-cli not found. Build it or set FATOORA_RS_CLI to its full path."
    exit 1
  fi
fi

if [ ! -f "${FIXTURE}" ]; then
  echo "fixture not found: ${FIXTURE}"
  exit 1
fi

mkdir -p "${OUT_DIR}"

hyperfine \
  --warmup 3 \
  --export-markdown "${OUT_FILE}" \
  --shell=none \
  -n "fatoora" \
  "\"${OFFICIAL_CLI}\" -generateHash -invoice \"${FIXTURE}\"" \
  -n "fatoora-rs-cli" \
  "\"${RS_CLI}\" generate-hash --invoice \"${FIXTURE}\""

echo "Wrote ${OUT_FILE}"
