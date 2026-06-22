use std::io::{BufRead, Write};

use crate::cli::InputFormat;
use crate::error::AppError;
use crate::json::redact_json_line;
use crate::redact::{RedactionCounts, Redactor};

pub const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

pub fn process(
    reader: &mut dyn BufRead,
    writer: &mut dyn Write,
    format: InputFormat,
    redactor: &Redactor,
) -> Result<RedactionCounts, AppError> {
    let mut counts = RedactionCounts::default();
    let mut line = Vec::new();
    let mut line_number = 0;

    loop {
        line_number += 1;
        let bytes_read = read_bounded_line(reader, &mut line, line_number)?;
        if bytes_read == 0 {
            break;
        }

        let line =
            std::str::from_utf8(&line).map_err(|_| AppError::InvalidUtf8 { line: line_number })?;
        let (content, ending) = split_line_ending(line);
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

fn read_bounded_line(
    reader: &mut dyn BufRead,
    line: &mut Vec<u8>,
    line_number: usize,
) -> Result<usize, AppError> {
    line.clear();

    loop {
        let available = reader.fill_buf().map_err(|source| AppError::ReadInput {
            line: line_number,
            source,
        })?;
        if available.is_empty() {
            return Ok(line.len());
        }

        let Some((take, reached_line_end)) = bounded_chunk(line.len(), available) else {
            return Err(AppError::LineTooLong {
                line: line_number,
                limit: MAX_LINE_BYTES,
            });
        };
        line.extend_from_slice(&available[..take]);
        reader.consume(take);

        if reached_line_end {
            return Ok(line.len());
        }
    }
}

fn bounded_chunk(current_length: usize, available: &[u8]) -> Option<(usize, bool)> {
    let (requested, reached_line_end) = available
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or((available.len(), false), |offset| (offset + 1, true));
    let next_length = current_length.checked_add(requested)?;
    if next_length <= MAX_LINE_BYTES {
        Some((requested, reached_line_end))
    } else {
        None
    }
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

    use super::{MAX_LINE_BYTES, process};

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
    fn rejects_lines_larger_than_the_stream_limit_before_writing_output() {
        let input = vec![b'a'; MAX_LINE_BYTES + 1];
        let mut input = Cursor::new(input);
        let mut output = Vec::new();

        let error = process(
            &mut input,
            &mut output,
            InputFormat::Text,
            &Redactor::support_safe(),
        )
        .unwrap_err();

        assert!(output.is_empty());
        assert!(error.to_string().contains("input line 1 exceeds"));
        assert!(!error.to_string().contains("aaaa"));
    }

    #[test]
    fn accepts_a_line_at_the_stream_limit() {
        let input = vec![b'a'; MAX_LINE_BYTES];
        let mut input = Cursor::new(input);
        let mut output = Vec::new();

        process(
            &mut input,
            &mut output,
            InputFormat::Text,
            &Redactor::support_safe(),
        )
        .unwrap();

        assert_eq!(output.len(), MAX_LINE_BYTES);
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
