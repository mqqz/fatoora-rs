#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
include_dir="${root_dir}/fatoora-ffi/include"
lib_dir="${root_dir}/target/debug"
examples_dir="${root_dir}/bindings/c/examples"
csr_props="${root_dir}/fatoora-core/tests/fixtures/csr-configs/csr-config-example-EN.properties"
signed_xml="${root_dir}/fatoora-core/tests/fixtures/invoices/sample-simplified-invoice.xml"
invoice_xml="${root_dir}/fatoora-core/tests/fixtures/invoices/sample-simplified-invoice.xml"

mapfile -t sources < <(find "${examples_dir}" -maxdepth 1 -name "*.c" | sort)
if [ ${#sources[@]} -eq 0 ]; then
  echo "no C examples found in ${examples_dir}" >&2
  exit 1
fi

outputs=()
cleanup() {
  for output in "${outputs[@]}"; do
    rm -f "${output}"
  done
}
trap cleanup EXIT

cargo build -p fatoora-ffi

for source in "${sources[@]}"; do
  base_name="$(basename "${source}" .c)"
  output="${examples_dir}/${base_name}"
  outputs+=("${output}")
  cc ${CFLAGS:-} \
    -DFATOORA_DOC_CSR_PROPS="\"${csr_props}\"" \
    -DFATOORA_DOC_SIGNED_XML="\"${signed_xml}\"" \
    -DFATOORA_DOC_INVOICE_XML="\"${invoice_xml}\"" \
    -I "${include_dir}" -L "${lib_dir}" -lfatoora_ffi \
    "${source}" \
    -o "${output}"
  echo "built: ${base_name}.c -> ${output}"
  echo "running: ${base_name}.c"
  if LD_LIBRARY_PATH="${lib_dir}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" "${output}"; then
    echo "ran: ${base_name}.c PASSED"
  else
    echo "ran: ${base_name}.c FAILED" >&2
    exit 1
  fi
done
