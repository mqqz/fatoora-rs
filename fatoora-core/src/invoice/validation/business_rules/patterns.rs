//! Bounded XPath regular expressions for the SDK's data-supplied currency patterns.
//! Syntax follows W3C XPath Functions 2.0 §7.6.1, including XML character classes.
use super::FailureKind;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

/// One invoice can reuse a pattern many times. Bound distinct nonliteral pairs,
/// including cached failures, so repeated amount nodes cannot amplify compilation.
#[derive(Default)]
pub(super) struct MatchCache(RefCell<BTreeMap<(String, String), Result<bool, FailureKind>>>);
impl MatchCache {
    pub fn matches(&self, input: &str, pattern: &str) -> Result<bool, FailureKind> {
        if input.len() > 4096 || pattern.len() > 4096 {
            return Err(FailureKind::Limit("regex bytes"));
        }
        if literal(pattern) {
            return Ok(input.contains(pattern));
        }
        let key = (input.to_owned(), pattern.to_owned());
        let mut values = self.0.borrow_mut();
        if let Some(result) = values.get(&key) {
            return result.clone();
        }
        if values.len() >= 128 {
            return Err(FailureKind::Limit("regex patterns"));
        }
        let result = matches(input, pattern);
        values.insert(key, result.clone());
        result
    }
}
fn literal(pattern: &str) -> bool {
    pattern
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
}

pub(super) fn matches(input: &str, pattern: &str) -> Result<bool, FailureKind> {
    if input.len() > 4096 || pattern.len() > 4096 {
        return Err(FailureKind::Limit("regex bytes"));
    }
    if literal(pattern) {
        return Ok(input.contains(pattern));
    }
    let mut parser = Translator {
        chars: pattern.chars().collect(),
        offset: 0,
        opened: 0,
        closed: BTreeSet::new(),
        groups: Vec::new(),
    };
    let translated = parser.pattern()?;
    let regex = fancy_regex::RegexBuilder::new(&translated)
        .backtrack_limit(100_000)
        .delegate_size_limit(256 * 1024)
        .delegate_dfa_size_limit(256 * 1024)
        .build()
        .map_err(|error| match error {
            fancy_regex::Error::CompileError(fancy_regex::CompileError::InnerError(e))
                if e.size_limit().is_some() =>
            {
                FailureKind::Limit("regex compiled bytes")
            }
            fancy_regex::Error::ParseError(_, fancy_regex::ParseError::RecursionExceeded) => {
                FailureKind::Limit("regex depth")
            }
            _ => FailureKind::InvalidRegex,
        })?;
    regex
        .is_match(input)
        .map_err(|_| FailureKind::Limit("regex execution"))
}
struct Translator {
    chars: Vec<char>,
    offset: usize,
    opened: usize,
    closed: BTreeSet<usize>,
    groups: Vec<Option<usize>>,
}
impl Translator {
    fn next(&mut self) -> Option<char> {
        let c = self.chars.get(self.offset).copied();
        self.offset += usize::from(c.is_some());
        c
    }
    fn peek(&self) -> Option<char> {
        self.chars.get(self.offset).copied()
    }
    fn pattern(&mut self) -> Result<String, FailureKind> {
        let mut out = String::new();
        while let Some(c) = self.next() {
            match c {
                '*' | '+' | '?' | '}' if self.peek() == Some('+') => {
                    return Err(FailureKind::InvalidRegex);
                }
                '[' => out.push_str(&self.class(0)?),
                '\\' => out.push_str(&self.escape(false)?),
                '.' => out.push_str("[^\\n\\r]"),
                '$' => out.push_str(r"\z"),
                '^' => out.push_str(r"\A"),
                '(' => {
                    if self.groups.len() >= 128 {
                        return Err(FailureKind::Limit("regex depth"));
                    }
                    if self.peek() == Some('?') {
                        self.next();
                        if self.next() != Some(':') {
                            return Err(FailureKind::InvalidRegex);
                        }
                        self.groups.push(None);
                        out.push_str("(?:");
                    } else {
                        self.opened += 1;
                        self.groups.push(Some(self.opened));
                        out.push('(');
                    }
                }
                ')' => {
                    if let Some(id) = self.groups.pop().ok_or(FailureKind::InvalidRegex)? {
                        self.closed.insert(id);
                    }
                    out.push(')');
                }
                _ => out.push(c),
            }
        }
        if !self.groups.is_empty() {
            return Err(FailureKind::InvalidRegex);
        }
        Ok(out)
    }
    fn class(&mut self, depth: usize) -> Result<String, FailureKind> {
        if depth >= 128 {
            return Err(FailureKind::Limit("regex depth"));
        }
        let mut out = String::from("[");
        if self.peek() == Some('^') {
            self.next();
            out.push('^');
        }
        let mut has_content = false;
        while let Some(c) = self.next() {
            match c {
                ']' if has_content => {
                    out.push(']');
                    return Ok(out);
                }
                ']' | '[' => return Err(FailureKind::InvalidRegex),
                '-' if self.peek() == Some('[') => {
                    if !has_content {
                        return Err(FailureKind::InvalidRegex);
                    }
                    self.next();
                    out.push_str("--");
                    out.push_str(&self.class(depth + 1)?);
                    if self.next() != Some(']') {
                        return Err(FailureKind::InvalidRegex);
                    }
                    out.push(']');
                    return Ok(out);
                }
                '\\' => out.push_str(&self.escape(true)?),
                '&' => out.push_str(r"\x{26}"),
                '^' => out.push_str(r"\x{5E}"),
                _ => out.push(c),
            }
            has_content = true;
        }
        Err(FailureKind::InvalidRegex)
    }
    fn escape(&mut self, in_class: bool) -> Result<String, FailureKind> {
        let c = self.next().ok_or(FailureKind::InvalidRegex)?;
        Ok(match c {
            's' => r"[ \t\n\r]".into(),
            'S' => r"[^ \t\n\r]".into(),
            'd' => r"\p{Nd}".into(),
            'D' => r"\P{Nd}".into(),
            'w' => r"[^\p{P}\p{Z}\p{C}]".into(),
            'W' => r"[\p{P}\p{Z}\p{C}]".into(),
            'i' | 'I' | 'c' | 'C' => format!(
                "[{}{}{}]",
                if c.is_uppercase() { "^" } else { "" },
                NAME_START,
                if matches!(c, 'c' | 'C') {
                    NAME_EXTRA
                } else {
                    ""
                }
            ),
            'p' | 'P' => {
                if self.next() != Some('{') {
                    return Err(FailureKind::InvalidRegex);
                }
                let mut name = String::new();
                loop {
                    match self.next() {
                        Some('}') => break,
                        Some(c) => name.push(c),
                        None => return Err(FailureKind::InvalidRegex),
                    }
                }
                if name == "Cs"
                    || matches!(
                        name.as_str(),
                        "IsHighSurrogates" | "IsHighPrivateUseSurrogates" | "IsLowSurrogates"
                    )
                {
                    // XML cannot contain surrogate code points.
                    if c == 'p' {
                        r"[^\s\S]".into()
                    } else {
                        r"[\s\S]".into()
                    }
                } else if let Some(block) = name.strip_prefix("Is") {
                    let (start, end) = block_range(block).ok_or(FailureKind::InvalidRegex)?;
                    format!(
                        "[{}\\x{{{start:X}}}-\\x{{{end:X}}}]",
                        if c == 'P' { "^" } else { "" }
                    )
                } else {
                    if !CATEGORIES.contains(&name.as_str()) {
                        return Err(FailureKind::InvalidRegex);
                    }
                    format!("\\{c}{{{name}}}")
                }
            }
            '1'..='9' if !in_class => {
                let mut id = (c as u8 - b'0') as usize;
                while let Some(d) = self.peek().and_then(|c| c.to_digit(10)) {
                    let next = id * 10 + d as usize;
                    if next > self.opened {
                        break;
                    }
                    self.next();
                    id = next;
                }
                if !self.closed.contains(&id) {
                    return Err(FailureKind::InvalidRegex);
                }
                // XPath treats a capture that did not participate as empty.
                format!("(?({id})\\{id}|)")
            }
            'n' | 'r' | 't' | '\\' | '|' | '.' | '?' | '*' | '+' | '(' | ')' | '{' | '}' | '-'
            | '[' | ']' | '^' | '$' => format!("\\{c}"),
            _ => return Err(FailureKind::InvalidRegex),
        })
    }
}
fn block_range(name: &str) -> Option<(u32, u32)> {
    static BLOCKS: LazyLock<BTreeMap<String, (u32, u32)>> = LazyLock::new(|| {
        let mut blocks = BTreeMap::new();
        // Unicode blocks begin on 16-code-point boundaries. The dependency
        // provides scalar lookup; collect each block once for name lookup.
        for code in (0..=0x10ffff).step_by(16) {
            if let Some(block) = char::from_u32(code).and_then(unicode_blocks::find_unicode_block) {
                blocks
                    .entry(block.name().replace(' ', ""))
                    .or_insert((block.start(), block.end()));
            }
        }
        for (alias, name) in [
            ("Greek", "GreekandCoptic"),
            ("PrivateUse", "PrivateUseArea"),
            ("CyrillicSupplementary", "CyrillicSupplement"),
        ] {
            if let Some(range) = blocks.get(name).copied() {
                blocks.insert(alias.into(), range);
            }
        }
        blocks
    });
    BLOCKS.get(name).copied()
}
const CATEGORIES: &[&str] = &[
    "L", "Lu", "Ll", "Lt", "Lm", "Lo", "M", "Mn", "Mc", "Me", "N", "Nd", "Nl", "No", "P", "Pc",
    "Pd", "Ps", "Pe", "Pi", "Pf", "Po", "Z", "Zs", "Zl", "Zp", "S", "Sm", "Sc", "Sk", "So", "C",
    "Cc", "Cf", "Co", "Cs", "Cn",
];
const NAME_START: &str = r":A-Z_a-z\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}";
const NAME_EXTRA: &str = r"\-.0-9\x{B7}\x{300}-\x{36F}\x{203F}-\x{2040}";
