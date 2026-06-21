use std::net::Ipv6Addr;
use std::str::FromStr;

const BEARER_REPLACEMENT: &str = "Bearer [REDACTED_BEARER_TOKEN]";
const API_KEY_REPLACEMENT: &str = "[REDACTED_API_KEY]";
const EMAIL_REPLACEMENT: &str = "[REDACTED_EMAIL]";
const IP_REPLACEMENT: &str = "[REDACTED_IP_ADDRESS]";
const HOME_PATH_REPLACEMENT: &str = "[REDACTED_HOME_PATH]";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RedactionCounts {
    pub bearer_tokens: usize,
    pub api_keys: usize,
    pub email_addresses: usize,
    pub ip_addresses: usize,
    pub home_paths: usize,
}

impl RedactionCounts {
    pub fn total(self) -> usize {
        self.bearer_tokens
            + self.api_keys
            + self.email_addresses
            + self.ip_addresses
            + self.home_paths
    }

    fn record(&mut self, category: Category) {
        match category {
            Category::BearerToken => self.bearer_tokens += 1,
            Category::ApiKey => self.api_keys += 1,
            Category::EmailAddress => self.email_addresses += 1,
            Category::IpAddress => self.ip_addresses += 1,
            Category::HomePath => self.home_paths += 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Redactor;

impl Redactor {
    pub fn support_safe() -> Self {
        Self
    }

    pub fn redact(&self, input: &str, counts: &mut RedactionCounts) -> String {
        let mut output = String::with_capacity(input.len());
        let mut cursor = 0;

        while cursor < input.len() {
            if let Some(found) = match_at(input, cursor) {
                output.push_str(&found.replacement);
                counts.record(found.category);
                cursor = found.end;
            } else {
                let character = input[cursor..]
                    .chars()
                    .next()
                    .expect("cursor remains on a valid character boundary");
                output.push(character);
                cursor += character.len_utf8();
            }
        }

        output
    }
}

#[derive(Clone, Copy, Debug)]
enum Category {
    BearerToken,
    ApiKey,
    EmailAddress,
    IpAddress,
    HomePath,
}

#[derive(Debug)]
struct RedactionMatch {
    end: usize,
    category: Category,
    replacement: String,
}

fn match_at(input: &str, start: usize) -> Option<RedactionMatch> {
    home_path_match(input, start)
        .or_else(|| bearer_match(input, start))
        .or_else(|| api_key_match(input, start))
        .or_else(|| email_match(input, start))
        .or_else(|| ipv4_match(input, start))
        .or_else(|| ipv6_match(input, start))
}

fn home_path_match(input: &str, start: usize) -> Option<RedactionMatch> {
    let bytes = input.as_bytes();
    let prefixes: &[&[u8]] = &[b"/Users/", b"/home/", b"~/"];
    let mut prefix_length = prefixes
        .iter()
        .find(|prefix| bytes[start..].starts_with(prefix))
        .map(|prefix| prefix.len());

    if prefix_length.is_none()
        && has_ascii_prefix(bytes, start, b"c:\\users\\")
        && boundary_before(bytes, start, is_path_byte)
    {
        prefix_length = Some(b"c:\\users\\".len());
    }

    let prefix_length = prefix_length?;
    if start > 0 && bytes[start - 1] == b'/' {
        return None;
    }

    let mut end = start + prefix_length;
    while end < bytes.len() && is_path_byte(bytes[end]) {
        end += 1;
    }

    if end == start + prefix_length && !bytes[start..].starts_with(b"~/") {
        return None;
    }

    Some(RedactionMatch {
        end,
        category: Category::HomePath,
        replacement: HOME_PATH_REPLACEMENT.to_owned(),
    })
}

fn bearer_match(input: &str, start: usize) -> Option<RedactionMatch> {
    let bytes = input.as_bytes();
    if !boundary_before(bytes, start, is_word_byte) || !has_ascii_prefix(bytes, start, b"bearer") {
        return None;
    }

    let mut token_start = start + b"bearer".len();
    if token_start >= bytes.len() || !bytes[token_start].is_ascii_whitespace() {
        return None;
    }
    while token_start < bytes.len() && bytes[token_start].is_ascii_whitespace() {
        token_start += 1;
    }

    let end = consume_while(bytes, token_start, is_token_byte);
    if end.saturating_sub(token_start) < 8 {
        return None;
    }

    Some(RedactionMatch {
        end,
        category: Category::BearerToken,
        replacement: BEARER_REPLACEMENT.to_owned(),
    })
}

fn api_key_match(input: &str, start: usize) -> Option<RedactionMatch> {
    let bytes = input.as_bytes();
    if !boundary_before(bytes, start, is_token_byte) {
        return None;
    }

    for prefix in [
        b"sk-".as_slice(),
        b"ghp_",
        b"gho_",
        b"ghu_",
        b"ghs_",
        b"ghr_",
    ] {
        if bytes[start..].starts_with(prefix) {
            let end = consume_while(bytes, start + prefix.len(), is_token_byte);
            if end - (start + prefix.len()) >= 16 {
                return Some(api_key_redaction(end));
            }
        }
    }

    if bytes[start..].starts_with(b"AKIA") {
        let end = consume_while(bytes, start + 4, |byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit()
        });
        if end - (start + 4) == 16 {
            return Some(api_key_redaction(end));
        }
    }

    for label in [
        b"api_key".as_slice(),
        b"api-key",
        b"apikey",
        b"access_token",
        b"access-token",
        b"token",
    ] {
        if !has_ascii_prefix(bytes, start, label) {
            continue;
        }

        let label_end = start + label.len();
        if label_end < bytes.len() && is_word_byte(bytes[label_end]) {
            continue;
        }

        let mut token_start = label_end;
        while token_start < bytes.len() && bytes[token_start].is_ascii_whitespace() {
            token_start += 1;
        }
        if token_start >= bytes.len() || !matches!(bytes[token_start], b':' | b'=') {
            continue;
        }
        token_start += 1;
        while token_start < bytes.len() && bytes[token_start].is_ascii_whitespace() {
            token_start += 1;
        }

        let end = consume_while(bytes, token_start, is_token_byte);
        if end - token_start >= 8 {
            let mut replacement = input[start..token_start].to_owned();
            replacement.push_str(API_KEY_REPLACEMENT);
            return Some(RedactionMatch {
                end,
                category: Category::ApiKey,
                replacement,
            });
        }
    }

    None
}

fn api_key_redaction(end: usize) -> RedactionMatch {
    RedactionMatch {
        end,
        category: Category::ApiKey,
        replacement: API_KEY_REPLACEMENT.to_owned(),
    }
}

fn email_match(input: &str, start: usize) -> Option<RedactionMatch> {
    let bytes = input.as_bytes();
    if !is_email_local_byte(*bytes.get(start)?)
        || !boundary_before(bytes, start, is_email_local_byte)
    {
        return None;
    }

    let local_end = consume_while(bytes, start, is_email_local_byte);
    if local_end == start
        || local_end >= bytes.len()
        || bytes[local_end] != b'@'
        || bytes[local_end - 1] == b'.'
    {
        return None;
    }

    let domain_start = local_end + 1;
    let end = consume_while(bytes, domain_start, is_domain_byte);
    let domain = &bytes[domain_start..end];
    let last_dot = domain.iter().rposition(|byte| *byte == b'.')?;
    if last_dot == 0
        || last_dot + 3 > domain.len()
        || domain.first() == Some(&b'-')
        || domain.get(last_dot.wrapping_sub(1)) == Some(&b'-')
        || domain.get(last_dot + 1) == Some(&b'-')
        || !domain[last_dot + 1..].iter().all(u8::is_ascii_alphabetic)
        || !boundary_after(bytes, end, is_domain_byte)
    {
        return None;
    }

    Some(RedactionMatch {
        end,
        category: Category::EmailAddress,
        replacement: EMAIL_REPLACEMENT.to_owned(),
    })
}

fn ipv4_match(input: &str, start: usize) -> Option<RedactionMatch> {
    let bytes = input.as_bytes();
    if !bytes.get(start)?.is_ascii_digit()
        || !boundary_before(bytes, start, |byte| byte.is_ascii_digit() || byte == b'.')
    {
        return None;
    }

    let mut cursor = start;
    for part_index in 0..4 {
        let part_start = cursor;
        cursor = consume_while(bytes, cursor, |byte| byte.is_ascii_digit());
        if cursor == part_start || cursor - part_start > 3 {
            return None;
        }

        let value = input[part_start..cursor].parse::<u16>().ok()?;
        if value > 255 {
            return None;
        }

        if part_index < 3 {
            if bytes.get(cursor) != Some(&b'.') {
                return None;
            }
            cursor += 1;
        }
    }

    if bytes.get(cursor).is_some_and(u8::is_ascii_digit)
        || (bytes.get(cursor) == Some(&b'.')
            && bytes.get(cursor + 1).is_some_and(u8::is_ascii_digit))
    {
        return None;
    }

    Some(RedactionMatch {
        end: cursor,
        category: Category::IpAddress,
        replacement: IP_REPLACEMENT.to_owned(),
    })
}

fn ipv6_match(input: &str, start: usize) -> Option<RedactionMatch> {
    let bytes = input.as_bytes();
    if !bytes
        .get(start)
        .is_some_and(|byte| byte.is_ascii_hexdigit() || *byte == b':')
        || !boundary_before(bytes, start, |byte| {
            byte.is_ascii_hexdigit() || byte == b':'
        })
    {
        return None;
    }

    let end = consume_while(bytes, start, |byte| {
        byte.is_ascii_hexdigit() || byte == b':'
    });
    let candidate = &input[start..end];
    if candidate.bytes().filter(|byte| *byte == b':').count() < 2
        || Ipv6Addr::from_str(candidate).is_err()
    {
        return None;
    }

    Some(RedactionMatch {
        end,
        category: Category::IpAddress,
        replacement: IP_REPLACEMENT.to_owned(),
    })
}

fn consume_while(bytes: &[u8], mut cursor: usize, predicate: impl Fn(u8) -> bool) -> usize {
    while bytes.get(cursor).copied().is_some_and(&predicate) {
        cursor += 1;
    }
    cursor
}

fn has_ascii_prefix(bytes: &[u8], start: usize, prefix: &[u8]) -> bool {
    bytes
        .get(start..start + prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

fn boundary_before(bytes: &[u8], start: usize, predicate: impl Fn(u8) -> bool) -> bool {
    start == 0 || !predicate(bytes[start - 1])
}

fn boundary_after(bytes: &[u8], end: usize, predicate: impl Fn(u8) -> bool) -> bool {
    end == bytes.len() || !predicate(bytes[end])
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'+' | b'/' | b'-' | b'=')
}

fn is_email_local_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_domain_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
}

fn is_path_byte(byte: u8) -> bool {
    !byte.is_ascii_whitespace()
        && !matches!(
            byte,
            b'"' | b'\'' | b'<' | b'>' | b'|' | b',' | b';' | b')' | b']' | b'}'
        )
}

#[cfg(test)]
mod tests {
    use super::{RedactionCounts, Redactor};

    #[test]
    fn redacts_all_support_safe_categories() {
        let input = concat!(
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature\n",
            "api_key=abcdefghijk123456789\n",
            "contact gale@example.com from 192.168.1.20 or 2001:db8::1\n",
            "read /Users/gale/Library/Logs/app.log"
        );
        let mut counts = RedactionCounts::default();

        let output = Redactor::support_safe().redact(input, &mut counts);

        assert!(!output.contains("eyJhbGci"));
        assert!(!output.contains("abcdefghijk"));
        assert!(!output.contains("gale@example.com"));
        assert!(!output.contains("192.168.1.20"));
        assert!(!output.contains("2001:db8::1"));
        assert!(!output.contains("/Users/gale"));
        assert_eq!(counts.bearer_tokens, 1);
        assert_eq!(counts.api_keys, 1);
        assert_eq!(counts.email_addresses, 1);
        assert_eq!(counts.ip_addresses, 2);
        assert_eq!(counts.home_paths, 1);
    }

    #[test]
    fn leaves_invalid_ip_candidates_unchanged() {
        let input = "version 999.2.3.4 and label dead:beef";
        let mut counts = RedactionCounts::default();

        let output = Redactor::support_safe().redact(input, &mut counts);

        assert_eq!(output, input);
        assert_eq!(counts.total(), 0);
    }

    #[test]
    fn preserves_generic_api_key_labels() {
        let mut counts = RedactionCounts::default();

        let output = Redactor::support_safe().redact("access_token: abcdefghijklmnop", &mut counts);

        assert_eq!(output, "access_token: [REDACTED_API_KEY]");
        assert_eq!(counts.api_keys, 1);
    }
}
