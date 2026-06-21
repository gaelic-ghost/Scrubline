use crate::redact::{RedactionCounts, Redactor};

const MAX_NESTING_DEPTH: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsonError {
    pub column: usize,
    pub reason: &'static str,
}

pub fn redact_json_line(
    input: &str,
    redactor: &Redactor,
    counts: &mut RedactionCounts,
) -> Result<String, JsonError> {
    let mut parser = Parser {
        input: input.as_bytes(),
        position: 0,
        redactor,
        counts,
    };
    let output = parser.parse_value(0, None)?;
    parser.skip_whitespace();
    if parser.position != parser.input.len() {
        return Err(parser.error("unexpected content after the JSON value"));
    }
    Ok(output)
}

struct Parser<'a> {
    input: &'a [u8],
    position: usize,
    redactor: &'a Redactor,
    counts: &'a mut RedactionCounts,
}

impl Parser<'_> {
    fn parse_value(&mut self, depth: usize, object_key: Option<&str>) -> Result<String, JsonError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(self.error("JSON nesting exceeds the supported limit of 128"));
        }

        self.skip_whitespace();
        match self.peek() {
            Some(b'"') => {
                let value = self.parse_string()?;
                let redacted = if let Some(key) = object_key {
                    self.redactor.redact_json_value(key, &value, self.counts)
                } else {
                    self.redactor.redact(&value, self.counts)
                };
                Ok(encode_string(&redacted))
            }
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b't') => self.parse_literal(b"true"),
            Some(b'f') => self.parse_literal(b"false"),
            Some(b'n') => self.parse_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            Some(_) => Err(self.error("expected a JSON value")),
            None => Err(self.error("expected a JSON value but reached the end of the line")),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<String, JsonError> {
        self.position += 1;
        let mut output = String::from("{");
        self.skip_whitespace();
        if self.consume(b'}') {
            output.push('}');
            return Ok(output);
        }

        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.error("expected a quoted object key"));
            }
            let key = self.parse_string()?;
            output.push_str(&encode_string(&key));

            self.skip_whitespace();
            if !self.consume(b':') {
                return Err(self.error("expected ':' after the object key"));
            }
            output.push(':');
            output.push_str(&self.parse_value(depth + 1, Some(&key))?);

            self.skip_whitespace();
            if self.consume(b'}') {
                output.push('}');
                return Ok(output);
            }
            if !self.consume(b',') {
                return Err(self.error("expected ',' or '}' after the object value"));
            }
            output.push(',');
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<String, JsonError> {
        self.position += 1;
        let mut output = String::from("[");
        self.skip_whitespace();
        if self.consume(b']') {
            output.push(']');
            return Ok(output);
        }

        loop {
            output.push_str(&self.parse_value(depth + 1, None)?);
            self.skip_whitespace();
            if self.consume(b']') {
                output.push(']');
                return Ok(output);
            }
            if !self.consume(b',') {
                return Err(self.error("expected ',' or ']' after the array value"));
            }
            output.push(',');
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        if !self.consume(b'"') {
            return Err(self.error("expected a JSON string"));
        }

        let mut output = String::new();
        while let Some(byte) = self.peek() {
            match byte {
                b'"' => {
                    self.position += 1;
                    return Ok(output);
                }
                b'\\' => {
                    self.position += 1;
                    self.parse_escape(&mut output)?;
                }
                0x00..=0x1f => {
                    return Err(self.error("unescaped control character in a JSON string"));
                }
                0x20..=0x7f => {
                    output.push(byte as char);
                    self.position += 1;
                }
                _ => {
                    let remaining = std::str::from_utf8(&self.input[self.position..])
                        .map_err(|_| self.error("invalid UTF-8 in a JSON string"))?;
                    let character = remaining
                        .chars()
                        .next()
                        .ok_or_else(|| self.error("incomplete UTF-8 in a JSON string"))?;
                    output.push(character);
                    self.position += character.len_utf8();
                }
            }
        }

        Err(self.error("unterminated JSON string"))
    }

    fn parse_escape(&mut self, output: &mut String) -> Result<(), JsonError> {
        let escaped = self
            .peek()
            .ok_or_else(|| self.error("unterminated escape sequence in a JSON string"))?;
        self.position += 1;
        match escaped {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{0008}'),
            b'f' => output.push('\u{000c}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => {
                let high = self.parse_hex_quad()?;
                let scalar = if (0xd800..=0xdbff).contains(&high) {
                    if !self.consume(b'\\') || !self.consume(b'u') {
                        return Err(
                            self.error("high surrogate must be followed by a low surrogate escape")
                        );
                    }
                    let low = self.parse_hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&low) {
                        return Err(self.error("invalid low surrogate in a Unicode escape"));
                    }
                    0x10000 + (((high - 0xd800) as u32) << 10) + (low - 0xdc00) as u32
                } else if (0xdc00..=0xdfff).contains(&high) {
                    return Err(self.error("unexpected low surrogate in a Unicode escape"));
                } else {
                    high as u32
                };
                let character = char::from_u32(scalar)
                    .ok_or_else(|| self.error("invalid Unicode scalar in a JSON string"))?;
                output.push(character);
            }
            _ => return Err(self.error("unsupported escape sequence in a JSON string")),
        }
        Ok(())
    }

    fn parse_hex_quad(&mut self) -> Result<u16, JsonError> {
        let end = self.position + 4;
        let digits = self
            .input
            .get(self.position..end)
            .ok_or_else(|| self.error("incomplete Unicode escape in a JSON string"))?;
        let mut value = 0_u16;
        for digit in digits {
            value = value
                .checked_mul(16)
                .and_then(|current| {
                    digit
                        .to_digit(16)
                        .map(|component| current + component as u16)
                })
                .ok_or_else(|| self.error("invalid hexadecimal digit in a Unicode escape"))?;
        }
        self.position = end;
        Ok(value)
    }

    fn parse_literal(&mut self, literal: &'static [u8]) -> Result<String, JsonError> {
        if self.input[self.position..].starts_with(literal) {
            self.position += literal.len();
            Ok(std::str::from_utf8(literal)
                .expect("JSON literals are valid UTF-8")
                .to_owned())
        } else {
            Err(self.error("invalid JSON literal"))
        }
    }

    fn parse_number(&mut self) -> Result<String, JsonError> {
        let start = self.position;
        self.consume(b'-');

        match self.peek() {
            Some(b'0') => {
                self.position += 1;
                if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(self.error("JSON numbers cannot contain leading zeroes"));
                }
            }
            Some(b'1'..=b'9') => {
                self.consume_digits();
            }
            _ => return Err(self.error("expected digits in a JSON number")),
        }

        if self.consume(b'.') {
            let fraction_start = self.position;
            self.consume_digits();
            if self.position == fraction_start {
                return Err(self.error("expected digits after the decimal point"));
            }
        }

        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            let exponent_start = self.position;
            self.consume_digits();
            if self.position == exponent_start {
                return Err(self.error("expected digits in the number exponent"));
            }
        }

        Ok(std::str::from_utf8(&self.input[start..self.position])
            .expect("JSON number tokens are ASCII")
            .to_owned())
    }

    fn consume_digits(&mut self) {
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.position += 1;
        }
    }

    fn skip_whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.position += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn error(&self, reason: &'static str) -> JsonError {
        let column = std::str::from_utf8(&self.input[..self.position])
            .map_or(self.position, |prefix| prefix.chars().count())
            + 1;
        JsonError { column, reason }
    }
}

fn encode_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{0000}'..='\u{001f}' => {
                use std::fmt::Write as _;
                write!(output, "\\u{:04x}", character as u32)
                    .expect("writing to an in-memory string cannot fail");
            }
            _ => output.push(character),
        }
    }
    output.push('"');
    output
}

trait HexDigit {
    fn to_digit(&self, radix: u32) -> Option<u32>;
}

impl HexDigit for u8 {
    fn to_digit(&self, radix: u32) -> Option<u32> {
        (*self as char).to_digit(radix)
    }
}

#[cfg(test)]
mod tests {
    use crate::redact::{RedactionCounts, Redactor};

    use super::redact_json_line;

    #[test]
    fn redacts_nested_string_values_without_changing_keys() {
        let input = r#"{"email":"gale@example.com","nested":["192.168.0.1",{"path":"/Users/gale/log.txt"}]}"#;
        let mut counts = RedactionCounts::default();

        let output = redact_json_line(input, &Redactor::support_safe(), &mut counts).unwrap();

        assert_eq!(
            output,
            r#"{"email":"[REDACTED_EMAIL]","nested":["[REDACTED_IP_ADDRESS]",{"path":"[REDACTED_HOME_PATH]"}]}"#
        );
        assert_eq!(counts.email_addresses, 1);
        assert_eq!(counts.ip_addresses, 1);
        assert_eq!(counts.home_paths, 1);
    }

    #[test]
    fn decodes_and_reencodes_unicode_escapes() {
        let input = r#"{"message":"hello \u263a \ud83d\ude80"}"#;
        let mut counts = RedactionCounts::default();

        let output = redact_json_line(input, &Redactor::support_safe(), &mut counts).unwrap();

        assert_eq!(output, r#"{"message":"hello ☺ 🚀"}"#);
    }

    #[test]
    fn rejects_trailing_json_content_without_echoing_it() {
        let input = r#"{"ok":true} secret"#;
        let mut counts = RedactionCounts::default();

        let error = redact_json_line(input, &Redactor::support_safe(), &mut counts).unwrap_err();

        assert_eq!(error.reason, "unexpected content after the JSON value");
    }

    #[test]
    fn redacts_labelled_json_values_including_escaped_keys() {
        let input = r#"{"api_key":"abcdefghijklmnop","access\u005ftoken":"qrstuvwxyz123456"}"#;
        let mut counts = RedactionCounts::default();

        let output = redact_json_line(input, &Redactor::support_safe(), &mut counts).unwrap();

        assert_eq!(
            output,
            r#"{"api_key":"[REDACTED_API_KEY]","access_token":"[REDACTED_API_KEY]"}"#
        );
        assert_eq!(counts.api_keys, 2);

        let mut second_counts = RedactionCounts::default();
        let second_output =
            redact_json_line(&output, &Redactor::support_safe(), &mut second_counts).unwrap();
        assert_eq!(second_output, output);
        assert_eq!(second_counts.total(), 0);
    }

    #[test]
    fn reports_unicode_aware_source_columns() {
        let input = "  {\"message\":\"🚀\",\"broken\":}";
        let mut counts = RedactionCounts::default();

        let error = redact_json_line(input, &Redactor::support_safe(), &mut counts).unwrap_err();

        assert_eq!(error.column, 27);
    }

    #[test]
    fn accepts_rfc_number_literal_escape_and_nesting_examples() {
        let valid = [
            "null",
            "true",
            "false",
            "0",
            "-0",
            "1.25",
            "-2.5e+10",
            r#""quote: \" slash: \/ control: \b\f\n\r\t""#,
            r#"{"array":[null,true,false,0,-1.2E-3],"object":{}}"#,
        ];

        for input in valid {
            let mut counts = RedactionCounts::default();
            let output = redact_json_line(input, &Redactor::support_safe(), &mut counts).unwrap();
            let mut second_counts = RedactionCounts::default();
            redact_json_line(&output, &Redactor::support_safe(), &mut second_counts).unwrap();
        }
    }

    #[test]
    fn rejects_invalid_rfc_number_literal_escape_and_surrogate_examples() {
        let invalid = [
            "",
            "01",
            "-",
            "1.",
            "1e",
            "True",
            r#""\x20""#,
            r#""\ud800""#,
            r#""\udc00""#,
            "[1,]",
            r#"{"a":1,}"#,
        ];

        for input in invalid {
            let mut counts = RedactionCounts::default();
            assert!(
                redact_json_line(input, &Redactor::support_safe(), &mut counts).is_err(),
                "expected invalid JSON to be rejected: {input:?}"
            );
        }
    }

    #[test]
    fn rejects_excessive_nesting() {
        let input = format!("{}0{}", "[".repeat(129), "]".repeat(129));
        let mut counts = RedactionCounts::default();

        let error = redact_json_line(&input, &Redactor::support_safe(), &mut counts).unwrap_err();

        assert_eq!(
            error.reason,
            "JSON nesting exceeds the supported limit of 128"
        );
    }

    #[test]
    fn generated_string_values_round_trip_through_parser_and_encoder() {
        let mut state = 0x5eed_cafe_u64;

        for _ in 0..512 {
            let mut value = String::new();
            for _ in 0..32 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let character = match state % 12 {
                    0 => '"',
                    1 => '\\',
                    2 => '\n',
                    3 => '\r',
                    4 => '\t',
                    5 => '\u{0000}',
                    6 => 'é',
                    7 => '🚀',
                    _ => char::from_u32(0x20 + (state % 0x5f) as u32).unwrap(),
                };
                value.push(character);
            }

            let encoded = super::encode_string(&value);
            let mut counts = RedactionCounts::default();
            let output =
                redact_json_line(&encoded, &Redactor::support_safe(), &mut counts).unwrap();
            let mut second_counts = RedactionCounts::default();
            let second_output =
                redact_json_line(&output, &Redactor::support_safe(), &mut second_counts).unwrap();

            assert_eq!(second_output, output);
            assert_eq!(second_counts.total(), 0);
        }
    }
}
