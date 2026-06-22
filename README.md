# Scrubline

Scrubline is a fast, deterministic command-line filter for removing
representative secrets and personal information from logs before they are
shared with support teams or AI tools.

It reads one bounded line at a time instead of loading the full input into
memory. Plain text is emitted with its original line endings. JSON Lines input
is parsed one value per line, scrubbed recursively inside string values, and
serialized back as valid JSONL.

## Quick start

Build with the pinned stable toolchain:

```sh
cargo build --release
```

Scrub standard input:

```sh
printf 'contact gale@example.com from 192.0.2.42\n' \
  | target/release/scrubline
```

Scrub a text file:

```sh
target/release/scrubline application.log --output application.safe.log
```

Scrub JSON Lines:

```sh
target/release/scrubline events.jsonl \
  --format jsonl \
  --output events.safe.jsonl
```

Scrubbed content goes to stdout unless `--output` is provided. Aggregate
counts go to stderr, so reports do not contaminate piped output. Use
`--no-report` when a silent diagnostic channel is required.

File output is staged in a hidden temporary file in the destination directory,
flushed and synced, and then moved into place only after the complete input
succeeds. Existing output is preserved when reading, JSON validation,
redaction, or writing fails. Scrubline also rejects direct, symbolic-link, and
Unix hard-link aliases between input and output. Normal failures clean up the
temporary file. Forced process termination, operating-system shutdown, or a
machine crash can still leave a hidden `.scrubline-*.tmp` file containing
scrubbed output in the destination directory; remove it only after verifying no
Scrubline process is still writing there.

Standard output remains truly streaming, so it can contain a successfully
scrubbed prefix when a later input line fails.

## Built-in `support-safe` policy

The initial policy is always enabled and replaces each detected value with a
category marker:

| Category | Representative matches | Replacement |
| --- | --- | --- |
| Bearer tokens | `Authorization: Bearer ...`-style values | `Bearer [REDACTED_BEARER_TOKEN]` |
| API keys | `sk-...`, GitHub-style prefixes, AWS access-key IDs, labelled token assignments, and labelled JSON string values | `[REDACTED_API_KEY]` |
| Email addresses | Conventional ASCII mailbox and domain forms | `[REDACTED_EMAIL]` |
| IP addresses | Valid IPv4 and IPv6 addresses | `[REDACTED_IP_ADDRESS]` |
| Home paths | macOS, Linux, tilde, and Windows user-home forms | `[REDACTED_HOME_PATH]` |

Reports contain counts only. Scrubline never includes a detected value in a
report or parse diagnostic.

Counts describe replacement operations. When categories overlap, the first
applicable policy rule owns the replacement; for example, an email inside a
home-directory path counts as one home-path redaction.

The policy is intentionally conservative and deterministic, not a claim that
every secret format can be recognized. Review scrubbed output before sharing
high-risk logs, especially when an application uses custom credential formats.

## JSONL behavior

`--format jsonl` requires every input line to contain exactly one valid JSON
value. Scrubline:

- redacts recursively inside JSON string values;
- leaves object keys and non-string values unchanged;
- emits compact valid JSON while preserving one output value per input line;
- preserves `LF`, `CRLF`, or a missing final line ending;
- accepts only JSON-defined whitespace around values;
- rejects nesting deeper than 128 levels to bound parser stack use;
- rejects lines larger than 8 MiB, including any line ending, to bound per-line
  processing;
- stops with a line-and-column diagnostic when input is invalid;
- never copies the malformed source value into that diagnostic.

The same 8 MiB line limit applies to plain-text input. Blank JSONL lines are
rejected because they are not JSON values.

## Exit status

- `0`: all input was scrubbed and written successfully.
- `1`: input, output, UTF-8, or JSONL processing failed.
- `2`: command-line arguments were invalid.

## Architecture

Scrubline is one binary package with six narrow internal surfaces:

- `cli`: parses the process contract without owning redaction behavior;
- `stream`: reads and writes incrementally and owns line preservation;
- `redact`: applies the built-in support-safe policy and counts matches;
- `json`: validates, normalizes, and recursively scrubs one JSON value;
- `output`: stages file output, rejects aliases, and commits only successful work;
- `error`: provides actionable diagnostics without source-value leakage.

This is a durable building-block design for the CLI. A library target is
deliberately deferred until an actual second consumer needs the redaction
engine as an API.

## Compatibility and development

Scrubline uses Rust edition 2024. The package MSRV is Rust 1.85, the first
stable release supporting edition 2024. Contributor and CI builds are pinned
to Rust 1.95.0 for reproducible formatting, linting, and release binaries.

Run the full local validation sequence serially:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
```

The current implementation has no runtime dependencies. Fixtures use reserved
domains and documentation IP ranges only.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
