use crate::{Diagnostic, Diagnostics, Span};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Kind {
    Word(String),
    String(String),
    LBrace,
    RBrace,
    LParen,
    RParen,
    Semicolon,
    Equal,
    EqualEqual,
    Bang,
    BangEqual,
    Tilde,
    BangTilde,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    AndAnd,
    OrOr,
    Comma,
    Colon,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    pub kind: Kind,
    pub span: Span,
}

pub(crate) fn lex(source: &str) -> Result<Vec<Token>, Diagnostics> {
    lex_at(source, 0)
}

pub(crate) fn lex_at(source: &str, base: usize) -> Result<Vec<Token>, Diagnostics> {
    let bytes = source.as_bytes();
    let mut at = 0;
    let mut tokens = Vec::new();
    let mut errors = Vec::new();

    while at < bytes.len() {
        match bytes[at] {
            b if b.is_ascii_whitespace() => at += 1,
            b'#' => {
                at += 1;
                while at < bytes.len() && bytes[at] != b'\n' {
                    at += 1;
                }
            }
            b'/' if bytes.get(at + 1) == Some(&b'/') => {
                at += 2;
                while at < bytes.len() && bytes[at] != b'\n' {
                    at += 1;
                }
            }
            b'/' if bytes.get(at + 1) == Some(&b'*') => {
                let start = at;
                at += 2;
                while at + 1 < bytes.len() && &bytes[at..at + 2] != b"*/" {
                    at += 1;
                }
                if at + 1 >= bytes.len() {
                    errors.push(Diagnostic::error(
                        Span::new(base + start, base + bytes.len()),
                        "unterminated block comment",
                    ));
                    break;
                }
                at += 2;
            }
            b'{' if bytes.get(at + 1) == Some(&b'"') => {
                // VCL long strings are delimited by {" and "}. Their
                // contents are literal: newlines and backslashes are not
                // escapes, which is why this cannot share the quoted-string
                // scanner below.
                let start = at;
                at += 2;
                let value_start = at;
                while at + 1 < bytes.len() && &bytes[at..at + 2] != b"\"}" {
                    at += source[at..]
                        .chars()
                        .next()
                        .expect("at is inside the source")
                        .len_utf8();
                }
                if at + 1 < bytes.len() {
                    let value = source[value_start..at].to_string();
                    at += 2;
                    tokens.push(Token {
                        kind: Kind::String(value),
                        span: Span::new(base + start, base + at),
                    });
                } else {
                    errors.push(Diagnostic::error(
                        Span::new(base + start, base + bytes.len()),
                        "unterminated long string literal",
                    ));
                    break;
                }
            }
            b'"' => {
                let start = at;
                at += 1;
                let mut value = String::new();
                let mut closed = false;
                while at < bytes.len() {
                    match bytes[at] {
                        b'"' => {
                            at += 1;
                            closed = true;
                            break;
                        }
                        b'\\' if at + 1 < bytes.len() => {
                            match bytes[at + 1] {
                                b'n' => value.push('\n'),
                                b'r' => value.push('\r'),
                                b't' => value.push('\t'),
                                b'"' => value.push('"'),
                                b'\\' => value.push('\\'),
                                // Regex escapes such as `\\.` and `\\d` are not
                                // string escapes. Preserve the slash and let the
                                // next iteration consume the following UTF-8
                                // character normally.
                                _ => {
                                    value.push('\\');
                                    at += 1;
                                    continue;
                                }
                            }
                            at += 2;
                        }
                        b'\n' | b'\r' => break,
                        byte if byte.is_ascii() => {
                            value.push(byte as char);
                            at += 1;
                        }
                        _ => {
                            let character = source[at..]
                                .chars()
                                .next()
                                .expect("at is inside the source");
                            value.push(character);
                            at += character.len_utf8();
                        }
                    }
                }
                if closed {
                    tokens.push(Token {
                        kind: Kind::String(value),
                        span: Span::new(base + start, base + at),
                    });
                } else {
                    errors.push(Diagnostic::error(
                        Span::new(base + start, base + at.max(start + 1)),
                        "unterminated string literal",
                    ));
                }
            }
            byte => {
                let (punctuation, width) = match (byte, bytes.get(at + 1).copied()) {
                    (b'=', Some(b'=')) => (Some(Kind::EqualEqual), 2),
                    (b'!', Some(b'=')) => (Some(Kind::BangEqual), 2),
                    (b'!', Some(b'~')) => (Some(Kind::BangTilde), 2),
                    (b'<', Some(b'=')) => (Some(Kind::LessEqual), 2),
                    (b'>', Some(b'=')) => (Some(Kind::GreaterEqual), 2),
                    (b'&', Some(b'&')) => (Some(Kind::AndAnd), 2),
                    (b'|', Some(b'|')) => (Some(Kind::OrOr), 2),
                    (b'!', _) => (Some(Kind::Bang), 1),
                    (b'~', _) => (Some(Kind::Tilde), 1),
                    (b'<', _) => (Some(Kind::Less), 1),
                    (b'>', _) => (Some(Kind::Greater), 1),
                    (b'+', _) => (Some(Kind::Plus), 1),
                    (b'-', _) => (Some(Kind::Minus), 1),
                    (b'*', _) => (Some(Kind::Star), 1),
                    (b'/', _) => (Some(Kind::Slash), 1),
                    (b'%', _) => (Some(Kind::Percent), 1),
                    (b'{', _) => (Some(Kind::LBrace), 1),
                    (b'}', _) => (Some(Kind::RBrace), 1),
                    (b'(', _) => (Some(Kind::LParen), 1),
                    (b')', _) => (Some(Kind::RParen), 1),
                    (b';', _) => (Some(Kind::Semicolon), 1),
                    (b'=', _) => (Some(Kind::Equal), 1),
                    (b',', _) => (Some(Kind::Comma), 1),
                    (b':', _) => (Some(Kind::Colon), 1),
                    _ => (None, 1),
                };
                if let Some(kind) = punctuation {
                    tokens.push(Token {
                        kind,
                        span: Span::new(base + at, base + at + width),
                    });
                    at += width;
                    continue;
                }
                if is_word_byte(byte) {
                    let start = at;
                    at += 1;
                    while at < bytes.len()
                        && is_word_byte(bytes[at])
                        && (bytes[at] != b'-' || source[start..at].contains(".http."))
                    {
                        at += 1;
                    }
                    tokens.push(Token {
                        kind: Kind::Word(source[start..at].to_string()),
                        span: Span::new(base + start, base + at),
                    });
                } else if byte.is_ascii() {
                    errors.push(Diagnostic::error(
                        Span::new(base + at, base + at + 1),
                        format!("unexpected character '{}'", byte as char),
                    ));
                    at += 1;
                } else {
                    let character = source[at..]
                        .chars()
                        .next()
                        .expect("at is inside the source");
                    errors.push(Diagnostic::error(
                        Span::new(base + at, base + at + character.len_utf8()),
                        format!("unexpected character '{character}'"),
                    ));
                    at += character.len_utf8();
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(tokens)
    } else {
        Err(Diagnostics::new(source, errors))
    }
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_headers_and_escaped_strings() {
        let source = "set req.http.X-Test = \"a\\n\";";
        let tokens = lex(source).unwrap();
        assert!(matches!(&tokens[1].kind, Kind::Word(w) if w == "req.http.X-Test"));
        assert!(matches!(&tokens[3].kind, Kind::String(w) if w == "a\n"));
        assert_eq!(
            &source[tokens[1].span.start..tokens[1].span.end],
            "req.http.X-Test"
        );
    }

    #[test]
    fn utf8_strings_round_trip_and_errors_render_safely() {
        let source = "std.log(\"blåbær\");";
        let tokens = lex(source).unwrap();
        assert!(matches!(&tokens[2].kind, Kind::String(value) if value == "blåbær"));

        let error = lex("é").unwrap_err().to_string();
        assert!(error.contains("unexpected character 'é'"));
    }

    #[test]
    fn block_comment_opener_at_exact_eof_is_unterminated() {
        let error = lex("vcl 4.1; /*").unwrap_err().to_string();
        assert!(error.contains("unterminated block comment"), "{error}");
    }

    #[test]
    fn long_strings_preserve_newlines_quotes_and_backslashes() {
        let source = "std.log({\"line one\\n\n\\\"quoted\\\"\"});";
        let tokens = lex(source).unwrap();
        assert!(matches!(
            &tokens[2].kind,
            Kind::String(value) if value == "line one\\n\n\\\"quoted\\\""
        ));

        let error = lex("std.log({\"never closed").unwrap_err().to_string();
        assert!(
            error.contains("unterminated long string literal"),
            "{error}"
        );
    }

    #[test]
    fn distinguishes_assignment_and_boolean_operators() {
        let tokens =
            lex("set req.http.X = true; if (true == false && !false || true != false || req.url ~ \"\\\\.m4s$\" || req.url !~ \"api\") {}").unwrap();
        assert!(tokens.iter().any(|token| token.kind == Kind::Equal));
        assert!(tokens.iter().any(|token| token.kind == Kind::EqualEqual));
        assert!(tokens.iter().any(|token| token.kind == Kind::BangEqual));
        assert!(tokens.iter().any(|token| token.kind == Kind::AndAnd));
        assert!(tokens.iter().any(|token| token.kind == Kind::OrOr));
        assert!(tokens.iter().any(|token| token.kind == Kind::Bang));
        assert!(tokens.iter().any(|token| token.kind == Kind::Tilde));
        assert!(tokens.iter().any(|token| token.kind == Kind::BangTilde));
        assert!(tokens
            .iter()
            .any(|token| matches!(&token.kind, Kind::String(value) if value == r"\.m4s$")));
    }

    #[test]
    fn distinguishes_arithmetic_from_header_hyphens() {
        let tokens = lex("req.http.X-Test-2 + 4-1 * 3 / 2 % 2 <= 9").unwrap();
        assert!(matches!(&tokens[0].kind, Kind::Word(word) if word == "req.http.X-Test-2"));
        assert!(matches!(tokens[1].kind, Kind::Plus));
        assert!(matches!(tokens[3].kind, Kind::Minus));
        assert!(matches!(tokens[5].kind, Kind::Star));
        assert!(matches!(tokens[7].kind, Kind::Slash));
        assert!(matches!(tokens[9].kind, Kind::Percent));
        assert!(matches!(tokens[11].kind, Kind::LessEqual));
    }
}
