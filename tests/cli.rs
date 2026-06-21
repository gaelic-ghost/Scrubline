use std::io::Write;
use std::process::{Command, Output, Stdio};

fn run_scrubline(arguments: &[&str], input: &str) -> Output {
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
        .write_all(input.as_bytes())
        .expect("fixture input should be writable");

    child.wait_with_output().expect("Scrubline should finish")
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
