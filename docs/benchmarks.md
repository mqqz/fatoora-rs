# Benchmarks

So far only invoice hash generation for invoices between ZATCA's SDK CLI and our CLI has been compared.
The plan is to expand this in the future.

CLI invoice hashing benchmark results:
- `bench/cli/results/hash_bench.md`
<!-- bench-table-start -->
| Command | Mean [ms] | Min [ms] | Max [ms] | Relative |
|:---|---:|---:|---:|---:|
| `fatoora` | 537.8 ± 8.6 | 522.0 | 549.1 | 187.35 ± 12.59 |
| `fatoora-rs-cli` | 2.9 ± 0.2 | 2.4 | 3.6 | 1.00 |
<!-- bench-table-end -->

The actual script for the benchmark is located at `bench/cli/hash_bench.sh`
