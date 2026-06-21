# AGENTS.md

## Purpose

Scrubline is a small Rust CLI that removes representative secrets and personal
information from logs before the logs are shared with support teams or AI
tools.

## Project Shape

- Keep Scrubline as one Rust 2024 binary package until a concrete second
  consumer earns a library target.
- Do not create a Cargo workspace for module organization alone.
- Keep command parsing, stream I/O, JSONL handling, redaction policy, and
  operator-facing errors in narrow modules with explicit inputs and outputs.
- Keep data flow unidirectional: CLI input selects processing behavior, the
  stream layer feeds values through the redactor, and aggregate counts flow
  back to the process edge.

## Product Safety

- Never include matched source values in diagnostics, reports, tests, or debug
  output.
- Keep stdout reserved for scrubbed content. Send reports and failures to
  stderr.
- Preserve valid JSONL by parsing each line as one JSON value and serializing
  one valid JSON value per output line.
- Preserve existing file destinations until the complete input succeeds. Keep
  stdout streaming and document that later failures can leave a scrubbed prefix.
- Keep the JSON nesting limit explicit and covered by regression tests.
- Keep redaction deterministic. New rules must document their matching
  boundary, replacement marker, and false-positive tradeoff.
- Use synthetic reserved-domain and documentation-range values in fixtures.

## Compatibility

- The package uses Rust edition 2024.
- `rust-version` is the compatibility contract and must not be raised silently.
- `rust-toolchain.toml` pins the contributor and CI toolchain. Keep rustfmt and
  Clippy aligned with that pin.
- Dependencies must come from crates.io or a public source repository. Do not
  commit machine-local dependency paths.

## Validation

Run these commands serially:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo +1.85.0 test --locked
cargo build --release
```

Add targeted unit tests for private matching or parsing behavior and
process-level integration tests for stdout, stderr, exit status, and CLI
contracts.

## Git

- Use Gale W <mail@galewilliams.com> for repository commits.
- Use scoped imperative commit subjects such as `runtime: stream support-safe
  redaction`.
- Do not publish the crate unless Gale explicitly requests that release step.
