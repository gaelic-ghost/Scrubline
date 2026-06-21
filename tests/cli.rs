use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn run_scrubline(arguments: &[&str], input: &str) -> Output {
    run_scrubline_bytes(arguments, input.as_bytes())
}

fn run_scrubline_bytes(arguments: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_scrubline"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Scrubline should start");

    child
        .stdin
        .as_mut()
        .expect("stdin should be piped")
        .write_all(input)
        .expect("fixture input should be writable");

    child.wait_with_output().expect("Scrubline should finish")
}

fn run_scrubline_files(input: &Path, output: &Path, format: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_scrubline"));
    command.arg(input).arg("--output").arg(output);
    if let Some(format) = format {
        command.arg("--format").arg(format);
    }
    command.output().expect("Scrubline should finish")
}

struct TempDirectory {
    path: PathBuf,
}

impl TempDirectory {
    fn new() -> Self {
        let sequence = TEMP_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("scrubline-tests-{}-{sequence}", std::process::id()));
        fs::create_dir(&path).expect("temporary directory should be created");
        Self { path }
    }

    fn join(&self, path: &str) -> PathBuf {
        self.path.join(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).expect("temporary directory should be removed");
    }
}

#[test]
fn scrubs_plain_text_and_reports_category_counts() {
    let output = run_scrubline(&[], include_str!("fixtures/plain-input.log"));

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        include_str!("fixtures/plain-expected.log")
    );
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        concat!(
            "scrubline: redacted 5 value(s) ",
            "(bearer_tokens=1, api_keys=1, email_addresses=1, ip_addresses=1, home_paths=1) ",
            "using policy support-safe\n"
        )
    );
}

#[test]
fn scrubs_jsonl_and_preserves_valid_line_oriented_json() {
    let output = run_scrubline(
        &["--format", "jsonl", "--no-report"],
        include_str!("fixtures/events-input.jsonl"),
    );

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        include_str!("fixtures/events-expected.jsonl")
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn invalid_json_diagnostic_does_not_echo_source_values() {
    let sensitive_marker = "synthetic-secret-that-must-not-leak";
    let input = format!(r#"{{"token":"{sensitive_marker}","broken":}}"#);

    let output = run_scrubline(&["--format=jsonl"], &input);
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(stderr.contains("invalid JSONL at line 1"));
    assert!(stderr.contains("no source value is included"));
    assert!(!stderr.contains(sensitive_marker));
}

#[test]
fn invalid_arguments_use_exit_status_two() {
    let output = run_scrubline(&["--format", "xml"], "");
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr.contains("choose 'text' or 'jsonl'"));
}

#[test]
fn unknown_option_diagnostic_does_not_echo_the_argument() {
    let sensitive_marker = "synthetic-private-option-value";

    let output = run_scrubline(&[&format!("--token={sensitive_marker}")], "");
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr.contains("an unknown option was provided"));
    assert!(!stderr.contains(sensitive_marker));
}

#[test]
fn invalid_utf8_fails_without_echoing_or_emitting_source_bytes() {
    let input = b"{\"ok\":true}\n\xffsynthetic-private-value\n";

    let output = run_scrubline_bytes(&["--format", "jsonl"], input);
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"{\"ok\":true}\n");
    assert!(stderr.contains("may not be valid UTF-8"));
    assert!(!stderr.contains("synthetic-private-value"));
}

#[test]
fn malformed_later_json_preserves_an_existing_output_file() {
    let directory = TempDirectory::new();
    let input = directory.join("input.jsonl");
    let output = directory.join("output.jsonl");
    fs::write(
        &input,
        "{\"email\":\"support@example.com\"}\n{\"secret\":\"abcdefghijklmnop\",\"broken\":}\n",
    )
    .unwrap();
    fs::write(&output, "existing-output\n").unwrap();

    let result = run_scrubline_files(&input, &output, Some("jsonl"));

    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read_to_string(&output).unwrap(), "existing-output\n");
    assert_eq!(fs::read_dir(&directory.path).unwrap().count(), 2);
}

#[test]
fn successful_file_output_replaces_the_destination_after_processing() {
    let directory = TempDirectory::new();
    let input = directory.join("input.log");
    let output = directory.join("output.log");
    fs::write(&input, "support@example.com\n").unwrap();
    fs::write(&output, "existing-output\n").unwrap();

    let result = run_scrubline_files(&input, &output, None);

    assert!(result.status.success());
    assert_eq!(fs::read_to_string(&output).unwrap(), "[REDACTED_EMAIL]\n");
    assert_eq!(fs::read_dir(&directory.path).unwrap().count(), 2);
}

#[cfg(unix)]
#[test]
fn successful_file_output_preserves_existing_permissions() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory = TempDirectory::new();
    let input = directory.join("input.log");
    let output = directory.join("output.log");
    fs::write(&input, "support@example.com\n").unwrap();
    fs::write(&output, "existing-output\n").unwrap();
    fs::set_permissions(&output, fs::Permissions::from_mode(0o640)).unwrap();

    let result = run_scrubline_files(&input, &output, None);

    assert!(result.status.success());
    assert_eq!(fs::metadata(&output).unwrap().mode() & 0o777, 0o640);
}

#[cfg(unix)]
#[test]
fn hard_link_output_alias_does_not_modify_the_source() {
    let directory = TempDirectory::new();
    let input = directory.join("input.log");
    let output = directory.join("hard-link.log");
    fs::write(&input, "support@example.com\n").unwrap();
    fs::hard_link(&input, &output).unwrap();

    let result = run_scrubline_files(&input, &output, None);

    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read_to_string(&input).unwrap(), "support@example.com\n");
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("refer to the same file")
    );
}

#[cfg(unix)]
#[test]
fn symbolic_link_output_alias_does_not_modify_the_source() {
    use std::os::unix::fs::symlink;

    let directory = TempDirectory::new();
    let input = directory.join("input.log");
    let output = directory.join("symbolic-link.log");
    fs::write(&input, "support@example.com\n").unwrap();
    symlink(&input, &output).unwrap();

    let result = run_scrubline_files(&input, &output, None);

    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read_to_string(&input).unwrap(), "support@example.com\n");
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("refer to the same file")
    );
}
