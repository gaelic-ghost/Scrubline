use std::io::{BufRead, Write};

use crate::cli::InputFormat;
use crate::error::AppError;
use crate::json::redact_json_line;
use crate::redact::{RedactionCounts, Redactor};

pub fn process(
    reader: &mut dyn BufRead,
    writer: &mut dyn Write,
    format: InputFormat,
    redactor: &Redactor,
) -> Result<RedactionCounts, AppError> {
    let mut counts = RedactionCounts::default();
    let mut line = String::new();
    let mut line_number = 0;

    loop {
        line.clear();
        line_number += 1;
        let bytes_read = reader
            .read_line(&mut line)
            .map_err(|source| AppError::ReadInput {
                line: line_number,
                source,
            })?;
        if bytes_read == 0 {
            break;
        }

        let (content, ending) = split_line_ending(&line);
        let scrubbed = match format {
            InputFormat::Text => redactor.redact(content, &mut counts),
            InputFormat::Jsonl => {
                if content
                    .bytes()
                    .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
                {
                    return Err(AppError::InvalidJson {
                        line: line_number,
                        column: 1,
                        reason: "expected one JSON value on every JSONL line",
                    });
                }
                redact_json_line(content, redactor, &mut counts).map_err(|error| {
                    AppError::InvalidJson {
                        line: line_number,
                        column: error.column,
                        reason: error.reason,
                    }
                })?
            }
        };

        writer
            .write_all(scrubbed.as_bytes())
            .and_then(|()| writer.write_all(ending.as_bytes()))
            .map_err(AppError::WriteOutput)?;
    }

    Ok(counts)
}

fn split_line_ending(line: &str) -> (&str, &str) {
    if let Some(content) = line.strip_suffix("\r\n") {
        (content, "\r\n")
    } else if let Some(content) = line.strip_suffix('\n') {
        (content, "\n")
    } else {
        (line, "")
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::cli::InputFormat;
    use crate::redact::Redactor;

    use super::process;

    #[test]
    fn processes_text_incrementally_and_preserves_line_endings() {
        let mut input = Cursor::new(b"gale@example.com\r\n192.168.1.1\n");
        let mut output = Vec::new();

        let counts = process(
            &mut input,
            &mut output,
            InputFormat::Text,
            &Redactor::support_safe(),
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "[REDACTED_EMAIL]\r\n[REDACTED_IP_ADDRESS]\n"
        );
        assert_eq!(counts.total(), 2);
    }

    #[test]
    fn rejects_blank_jsonl_lines() {
        let mut input = Cursor::new(b"{\"ok\":true}\n\n");
        let mut output = Vec::new();

        let error = process(
            &mut input,
            &mut output,
            InputFormat::Jsonl,
            &Redactor::support_safe(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("line 2"));
    }

    #[test]
    fn rejects_non_json_unicode_whitespace() {
        let mut input = Cursor::new("\u{00a0}{\"ok\":true}\n".as_bytes());
        let mut output = Vec::new();

        let error = process(
            &mut input,
            &mut output,
            InputFormat::Jsonl,
            &Redactor::support_safe(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("column 1"));
    }

    #[test]
    fn reports_columns_from_the_untrimmed_source_line() {
        let mut input = Cursor::new(b"  {\"ok\":}\n");
        let mut output = Vec::new();

        let error = process(
            &mut input,
            &mut output,
            InputFormat::Jsonl,
            &Redactor::support_safe(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("column 9"));
    }

    #[test]
    fn preserves_jsonl_crlf_and_missing_final_newline() {
        let mut input = Cursor::new(b"{\"ok\":true}\r\n{\"ok\":false}");
        let mut output = Vec::new();

        process(
            &mut input,
            &mut output,
            InputFormat::Jsonl,
            &Redactor::support_safe(),
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "{\"ok\":true}\r\n{\"ok\":false}"
        );
    }
}
