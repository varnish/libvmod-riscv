//! Compile-time validation of the regular-expression literals a policy spells.
//!
//! Every VCL pattern is a string literal — `~`, `!~`, `regsub`, `regsuball`
//! and the vmod `_regex` forms all refuse a computed pattern — so the compiler
//! sees all of them and can refuse a broken one here rather than let the host
//! discover it. That matters because the host cannot *report* it: a pattern
//! `regex::Regex::new` rejects simply never matches
//! (`Syscall::RegexMatch` in `interpreter.rs`, `sys_regex_*` on the real host),
//! so `if (req.url ~ "(unclosed")` would quietly pass everything through
//! instead of failing the reload.
//!
//! This is deliberately a *structural* check and not a second regex parser.
//! `vcl-compiler` has no runtime dependencies — the sandbox plan compiles the
//! whole crate to a RISC-V guest — so pulling `regex-syntax` in to gain exact
//! parity is not a trade worth making for typo detection. The rule that keeps
//! that honest is one-directional: this module may only reject a pattern the
//! `regex` crate also rejects. `tests/regex_parity.rs` is what enforces it,
//! by building every rejected pattern with the real engine.
//!
//! It is not the only gate, and it is not the last one. Every pattern a policy
//! publishes is built for real by `carapace_scripting::PatternSet::compile`,
//! which `ScriptEngine::warm` calls — so a pattern this module waves through
//! and the host cannot build still refuses the configuration candidate, at
//! `--test` and on reload, naming the pattern and the engine's own reason.
//! What this module adds is the *source position*: a refusal here points at
//! the line of VCL, a refusal there points at the script. That is the whole
//! trade, and it is why under-approximating costs an operator only a worse
//! error message while over-approximating costs them a policy that would have
//! worked. Keep the asymmetry in that order.

/// Longest pattern the host will read out of the guest, mirroring
/// `carapace_scripting::abi::Limits::MAX_PATTERN`.
///
/// Mirrored rather than imported: `vcl-compiler` has no runtime dependency on
/// `carapace-scripting`, and the sandbox plan wants to keep it that way.
/// `tests/regex_parity.rs` is where the two are pinned together, so a drift
/// is a failing test rather than a build error.
pub const MAX_PATTERN: usize = 4 * 1024;

/// Compiled-program ceiling the host builds every pattern under, mirroring
/// `carapace_scripting::abi::Limits::REGEX_SIZE_LIMIT`.
pub const REGEX_SIZE_LIMIT: usize = 64 * 1024;

/// Expanded-atom count above which a pattern certainly exceeds
/// [`REGEX_SIZE_LIMIT`].
///
/// The host refuses a pattern whose expansion reaches roughly 2 000 atoms — a
/// plain 2 042-byte literal is already over — so refusing at twice that is
/// well inside the one-directional rule while still catching the shape that
/// matters, a repetition of a repetition.
///
/// The count [`validate`] keeps is one unit per literal, class or escape;
/// a concatenation sums, a repetition multiplies the atom it follows, and an
/// alternation is charged its *longest* branch rather than the sum of them.
/// The sum is what a naive reading suggests, but the `regex` crate folds an
/// alternation of single characters into one character class, so
/// `(?:0|1|2|3|4|5|6|7|8|9){500}` costs 500 atoms there and not 5 000 —
/// charging the sum invented a refusal for a pattern the host builds. Taking
/// the longest branch is exact for that fold and an under-estimate for every
/// other alternation, which is the side of the one-directional rule this
/// module is allowed to be wrong on.
const MAX_EXPANSION: u64 = 4096;

/// Reject a pattern the host's regex engine could not build.
///
/// `Ok(())` means "not obviously broken", not "valid": a pattern this accepts
/// can still fail to compile on the host. The reverse never holds.
pub(crate) fn validate(pattern: &str) -> Result<(), String> {
    if pattern.len() > MAX_PATTERN {
        return Err(format!(
            "the pattern is {} bytes; the host reads at most {MAX_PATTERN}",
            pattern.len()
        ));
    }
    let bytes = pattern.as_bytes();
    let mut at = 0usize;
    let mut groups: Vec<usize> = Vec::new();
    // Whether a repetition operator at this position has something to repeat.
    let mut atom = false;
    // Expanded-atom accounting: one frame per open group, holding the enclosing
    // branch's running cost and its best completed branch. `cost` is the branch
    // being read, `branch` the longest one already closed by a '|', and `last`
    // the most recent atom, which is what a following repetition multiplies.
    let mut frames: Vec<(u64, u64)> = Vec::new();
    let mut cost: u64 = 0;
    let mut branch: u64 = 0;
    let mut last: u64 = 0;

    while at < bytes.len() {
        match bytes[at] {
            b'\\' => {
                let Some(&escaped) = bytes.get(at + 1) else {
                    return Err("the pattern ends in a trailing backslash".to_string());
                };
                at = escape_end(pattern, at, escaped)?;
                last = 1;
                cost = cost.saturating_add(1);
                atom = true;
            }
            b'[' => {
                let Some(end) = class_end(bytes, at) else {
                    return Err("a character class '[' is never closed".to_string());
                };
                check_class(&pattern[at..=end])?;
                at = end + 1;
                last = 1;
                cost = cost.saturating_add(1);
                atom = true;
            }
            b'(' => {
                if let Some(kind) = lookaround(&bytes[at..]) {
                    return Err(format!(
                        "'{kind}' is a look-around, which the host's regex engine does not have"
                    ));
                }
                groups.push(at);
                frames.push((cost, branch));
                cost = 0;
                branch = 0;
                last = 0;
                at += 1;
                // `(?i)`, `(?:`, `(?<name>`: the '?' opens a group flag, not a
                // repetition, so it must not reach the quantifier arm below.
                if bytes.get(at) == Some(&b'?') {
                    at += 1;
                }
                atom = false;
            }
            b')' => {
                if groups.pop().is_none() {
                    return Err("an unmatched ')' closes a group that was never opened".to_string());
                }
                let inner = branch.max(cost);
                let (outer_cost, outer_branch) = frames.pop().unwrap_or((0, 0));
                cost = outer_cost.saturating_add(inner);
                branch = outer_branch;
                last = inner;
                at += 1;
                atom = true;
            }
            b'|' => {
                // Nothing precedes an alternation's next branch, so nothing
                // is repeatable and nothing is left to multiply. The branch
                // just closed competes for the group's cost; see MAX_EXPANSION
                // for why the branches are maximised rather than summed.
                branch = branch.max(cost);
                cost = 0;
                last = 0;
                at += 1;
                atom = false;
            }
            // `a*?` and `a+?` are lazy forms, so a quantifier stays repeatable.
            b'*' | b'+' | b'?' => {
                if !atom {
                    return Err(format!(
                        "the repetition operator '{}' has nothing to repeat",
                        bytes[at] as char
                    ));
                }
                at += 1;
            }
            b'{' => match repetition(bytes, at) {
                Some((min, max, end)) => {
                    if !atom {
                        return Err(
                            "the repetition operator '{...}' has nothing to repeat".to_string()
                        );
                    }
                    if max.is_some_and(|max| max < min) {
                        let max = max.expect("checked by is_some_and");
                        return Err(format!("the repetition range {{{min},{max}}} counts down"));
                    }
                    // `{n,}` compiles as n copies followed by a `+`, so the
                    // bounded part is what expands.
                    let repeats = max.unwrap_or(min);
                    cost = cost.saturating_sub(last);
                    last = last.saturating_mul(repeats);
                    cost = cost.saturating_add(last);
                    if cost > MAX_EXPANSION {
                        return Err(format!(
                            "the pattern expands to more than {MAX_EXPANSION} repeated elements, \
                             past the host's {REGEX_SIZE_LIMIT}-byte compiled-size limit"
                        ));
                    }
                    at = end;
                }
                // Unlike PCRE, the host's engine has no literal '{': a brace
                // that does not open a repetition is an error there, so it is
                // one here. `\{` is the way to spell the character.
                None => {
                    return Err(
                        "'{' is a repetition operator; write '\\{' for a literal brace".to_string(),
                    )
                }
            },
            _ => {
                at += character_width(pattern, at);
                last = 1;
                cost = cost.saturating_add(1);
                atom = true;
            }
        }
    }

    if groups.is_empty() {
        Ok(())
    } else {
        Err("a group '(' is never closed".to_string())
    }
}

/// Index just past the escape that starts at `at`, or the reason the host's
/// engine would not know it.
///
/// The set of one-character escapes is the one the `regex` crate documents,
/// verified against it in `tests/regex_parity.rs`. Anything outside it —
/// `\Z`, `\K`, `\G`, `\h`, `\R`, `\Q`, an escaped non-ASCII character — is a
/// parse error there, and used to be accepted here on the "any non-digit
/// escape is fine" rule, which is how a `~` deny rule could compile and then
/// never fire.
fn escape_end(pattern: &str, at: usize, escaped: u8) -> Result<usize, String> {
    let bytes = pattern.as_bytes();
    if escaped.is_ascii_digit() {
        return Err(format!(
            "'\\{}' is a backreference or octal escape, and the host's regex engine has neither",
            escaped as char
        ));
    }
    if matches!(escaped, b'p' | b'P' | b'x' | b'u' | b'U') {
        return escape_argument_end(bytes, at, escaped);
    }
    // `\b{start}` and `\b{end}` are word-boundary assertions, not `\b`
    // repeated: the brace belongs to the escape.
    if escaped == b'b' && bytes.get(at + 2) == Some(&b'{') {
        return escape_argument_end(bytes, at, escaped);
    }
    if is_escapable(escaped) {
        return Ok(at + 2);
    }
    let spelled = pattern[at + 1..]
        .chars()
        .next()
        .map_or_else(|| escaped as char, |character| character);
    Err(format!(
        "'\\{spelled}' is not an escape the host's regex engine knows"
    ))
}

/// The one-character escapes `regex` accepts: every printable non-alphanumeric
/// ASCII byte, plus the sixteen letters that spell a class, an anchor or a
/// control character.
fn is_escapable(byte: u8) -> bool {
    matches!(
        byte,
        b'A' | b'B'
            | b'D'
            | b'S'
            | b'W'
            | b'a'
            | b'b'
            | b'd'
            | b'f'
            | b'n'
            | b'r'
            | b's'
            | b't'
            | b'v'
            | b'w'
            | b'z'
    ) || byte == b' '
        || (byte.is_ascii_graphic() && !byte.is_ascii_alphanumeric())
}

/// `\p{Greek}`, `\pL`, `\x41`, `\x{1F600}`, `\u00e9`, `\U0001F600`: the five
/// escapes that carry an argument.
///
/// The braced forms have to be consumed here rather than left to the caller,
/// or the `{` would reach the repetition arm and be reported as "'{' is a
/// repetition operator" — a refusal of a pattern the host builds happily.
fn escape_argument_end(bytes: &[u8], at: usize, escaped: u8) -> Result<usize, String> {
    let start = at + 2;
    if bytes.get(start) == Some(&b'{') {
        let Some(offset) = bytes[start..].iter().position(|byte| *byte == b'}') else {
            return Err(format!(
                "'\\{}' opens a '{{' that is never closed",
                escaped as char
            ));
        };
        return Ok(start + offset + 1);
    }
    if matches!(escaped, b'p' | b'P') {
        return match bytes.get(start) {
            Some(name) if name.is_ascii_alphabetic() => Ok(start + 1),
            _ => Err(format!(
                "'\\{}' needs a one-letter class or a braced name",
                escaped as char
            )),
        };
    }
    let digits = match escaped {
        b'x' => 2,
        b'u' => 4,
        _ => 8,
    };
    let end = start + digits;
    if bytes.len() < end || !bytes[start..end].iter().all(u8::is_ascii_hexdigit) {
        return Err(format!(
            "'\\{}' needs {digits} hex digits or a braced code point",
            escaped as char
        ));
    }
    Ok(end)
}

/// Width in bytes of the character starting at `at`, which is always inside
/// `pattern` and always on a character boundary when this is called.
fn character_width(pattern: &str, at: usize) -> usize {
    pattern[at..]
        .chars()
        .next()
        .map_or(1, |character| character.len_utf8())
}

/// The four PCRE look-arounds, spelled as they appear.
fn lookaround(rest: &[u8]) -> Option<&'static str> {
    ["(?=", "(?!", "(?<=", "(?<!"]
        .into_iter()
        .find(|&candidate| rest.starts_with(candidate.as_bytes()))
        .map(|v| v as _)
}

/// Index of the ']' closing the class that opens at `at`, if there is one.
///
/// A ']' first in the class is a literal, as is one inside a POSIX name; a
/// nested class is not tracked, which can only end a class early and so can
/// only lose a rejection, never invent one.
fn class_end(bytes: &[u8], at: usize) -> Option<usize> {
    let mut i = at + 1;
    if bytes.get(i) == Some(&b'^') {
        i += 1;
    }
    if bytes.get(i) == Some(&b']') {
        i += 1;
    }
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'[' if bytes.get(i + 1) == Some(&b':') => {
                match bytes[i + 2..].windows(2).position(|pair| pair == b":]") {
                    Some(offset) => i += 2 + offset + 2,
                    None => i += 1,
                }
            }
            b']' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Refuse a descending literal range such as `[z-a]`.
///
/// Only plain single-byte endpoints are compared. A range built from escapes
/// or from a nested class is left alone rather than guessed at.
fn check_class(class: &str) -> Result<(), String> {
    let bytes = class.as_bytes();
    let mut i = 1;
    if bytes.get(i) == Some(&b'^') {
        i += 1;
    }
    let mut previous: Option<u8> = None;
    while i + 1 < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 2;
                previous = None;
            }
            b'-' if i + 1 < bytes.len() - 1 => {
                let end = bytes[i + 1];
                if let (Some(start), true) = (previous, end.is_ascii() && end != b'\\') {
                    if end < start {
                        return Err(format!(
                            "the character range '{}-{}' counts down",
                            start as char, end as char
                        ));
                    }
                }
                i += 2;
                previous = None;
            }
            byte => {
                previous = byte.is_ascii().then_some(byte);
                i += 1;
            }
        }
    }
    Ok(())
}

/// Decode `{n}`, `{n,}` or `{n,m}` at `at`, returning the bounds and the index
/// just past the closing brace. `None` means the brace is a literal.
fn repetition(bytes: &[u8], at: usize) -> Option<(u64, Option<u64>, usize)> {
    let mut i = at + 1;
    let min_start = i;
    while bytes.get(i).is_some_and(u8::is_ascii_digit) {
        i += 1;
    }
    if i == min_start {
        return None;
    }
    let min = std::str::from_utf8(&bytes[min_start..i])
        .ok()?
        .parse()
        .ok()?;
    if bytes.get(i) == Some(&b'}') {
        return Some((min, Some(min), i + 1));
    }
    if bytes.get(i) != Some(&b',') {
        return None;
    }
    i += 1;
    let max_start = i;
    while bytes.get(i).is_some_and(u8::is_ascii_digit) {
        i += 1;
    }
    if bytes.get(i) != Some(&b'}') {
        return None;
    }
    let max = if i == max_start {
        None
    } else {
        Some(
            std::str::from_utf8(&bytes[max_start..i])
                .ok()?
                .parse()
                .ok()?,
        )
    };
    Some((min, max, i + 1))
}

#[cfg(test)]
mod tests {
    use super::{validate, REGEX_SIZE_LIMIT};

    #[test]
    fn accepts_the_patterns_carapace_policies_actually_spell() {
        for pattern in [
            "",
            "^/api/",
            r"\.(jpg|jpeg|png|gif|css|js|woff2?)(\?.*)?$",
            "(?i)^x-",
            "(?:foo|bar)\\.example\\.com",
            "a{2,4}",
            "a{2,}",
            "a{2}",
            "[a-z0-9_-]+",
            "[]]",
            "[^]]",
            "[[:alpha:]]+",
            "x*?",
            "x+?",
            "x??",
            r"\{literal\}",
            "^$",
            "[а-я]+",
            r"\\",
            r"\p{L}+",
            r"\P{Greek}",
            r"\pL",
            r"\x41",
            r"\x{1F600}",
            r"\u00e9",
            r"\U0001F600",
            r"\b{start}",
            "a{2000}",
            // An alternation of single characters is one character class to
            // the host, so these are 500 and 600 atoms, not 5 000 and 4 800.
            "(?:0|1|2|3|4|5|6|7|8|9){500}",
            "(?:a|b|c|d|e|f|g|h){600}",
        ] {
            assert!(validate(pattern).is_ok(), "{pattern:?}");
        }
    }

    #[test]
    fn names_the_break_in_a_broken_pattern() {
        for (pattern, needle) in [
            ("(unclosed", "never closed"),
            ("unopened)", "unmatched ')'"),
            ("[a-", "never closed"),
            ("*bad", "nothing to repeat"),
            ("a|*b", "nothing to repeat"),
            ("(*b)", "nothing to repeat"),
            ("a{2,1}", "counts down"),
            ("[z-a]", "counts down"),
            (r"a\", "trailing backslash"),
            (r"(a)\1", "backreference"),
            ("(?=x)", "look-around"),
            ("(?<!x)y", "look-around"),
            (r"a\Z", "not an escape"),
            (r"\Qliteral\E", "not an escape"),
            (r"\h", "not an escape"),
            (r"\R", "not an escape"),
            (r"\K", "not an escape"),
            (r"\G", "not an escape"),
            (r"\0", "backreference or octal"),
            (r"\p{Greek", "never closed"),
            (r"\x4", "hex digits"),
            ("(a{1000}){1000}", "compiled-size limit"),
            ("(a{65}){65}", "compiled-size limit"),
            ("(?:0|1|2|3|4|5|6|7|8|9){5000}", "compiled-size limit"),
        ] {
            let error = validate(pattern).expect_err(&format!("{pattern:?} was not refused"));
            assert!(error.contains(needle), "{pattern:?} reported {error:?}");
        }
    }

    /// The one-way property, over patterns nobody would write on purpose.
    ///
    /// Every string up to three characters long over a metacharacter-dense
    /// alphabet. Anything [`validate`] refuses here has to be something the
    /// real engine refuses too; the converse is explicitly allowed to fail,
    /// because this is an approximation and not a parser.
    #[test]
    fn a_refusal_is_never_invented_for_a_buildable_pattern() {
        const ALPHABET: &[u8] = b"ab()[]{}|*+?\\-^$.,1:pxZQ";
        let mut checked = 0usize;
        let mut refused = 0usize;
        for length in 0..=4u32 {
            let combinations = (ALPHABET.len() as u64).pow(length);
            for mut index in 0..combinations {
                let mut pattern = String::new();
                for _ in 0..length {
                    pattern.push(ALPHABET[(index % ALPHABET.len() as u64) as usize] as char);
                    index /= ALPHABET.len() as u64;
                }
                checked += 1;
                let Err(reason) = validate(&pattern) else {
                    continue;
                };
                refused += 1;
                assert!(
                    regex::RegexBuilder::new(&pattern)
                        .size_limit(REGEX_SIZE_LIMIT)
                        .build()
                        .is_err(),
                    "{pattern:?} builds fine but was refused: {reason}"
                );
            }
        }
        assert!(
            checked > 300_000,
            "the walk only covered {checked} patterns"
        );
        assert!(
            refused > checked / 10,
            "only {refused} of {checked} patterns were refused, so the walk proves little"
        );
    }
}
