//! Minimal ECMA-262-compatible pattern matcher for the receipt schema.
//! Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
//!
//! Supports: ^ $ literals, escaped punctuation, [classes] with ranges, (groups)
//! with |, and quantifiers * + ? {n} {m,n}. Anything else (\d, \w, ., lookaround,
//! backrefs) is rejected at compile time — fail closed, never misinterpreted.
//! Search semantics match JSON Schema: unanchored unless ^/$ are used.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError(pub String);
impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported pattern: {}", self.0)
    }
}
impl std::error::Error for PatternError {}

#[derive(Debug, Clone)]
enum Atom {
    Char(char),
    Class(Vec<(char, char)>, bool),
    Group(Vec<Vec<Item>>),
    Start,
    End,
}

#[derive(Debug, Clone)]
struct Item {
    atom: Atom,
    min: usize,
    max: usize,
}

#[derive(Debug, Clone)]
pub struct Pattern {
    alts: Vec<Vec<Item>>,
}

const ESCAPABLE: &str = ".\\$^-[](){}|*+?/:";

struct P<'a> {
    c: Vec<char>,
    i: usize,
    src: &'a str,
}

impl<'a> P<'a> {
    fn err<T>(&self, m: &str) -> Result<T, PatternError> {
        Err(PatternError(format!("{m} in {:?} at {}", self.src, self.i)))
    }
    fn alts(&mut self) -> Result<Vec<Vec<Item>>, PatternError> {
        let mut alts = vec![self.seq()?];
        while self.c.get(self.i) == Some(&'|') {
            self.i += 1;
            alts.push(self.seq()?);
        }
        Ok(alts)
    }
    fn seq(&mut self) -> Result<Vec<Item>, PatternError> {
        let mut items = Vec::new();
        while let Some(&ch) = self.c.get(self.i) {
            if ch == '|' || ch == ')' {
                break;
            }
            let atom = self.atom()?;
            let (min, max) = self.quant()?;
            if matches!(atom, Atom::Start | Atom::End) && (min, max) != (1, 1) {
                return self.err("quantified anchor");
            }
            items.push(Item { atom, min, max });
        }
        Ok(items)
    }
    fn atom(&mut self) -> Result<Atom, PatternError> {
        let ch = self.c[self.i];
        self.i += 1;
        match ch {
            '^' => Ok(Atom::Start),
            '$' => Ok(Atom::End),
            '(' => {
                if self.c.get(self.i) == Some(&'?') {
                    return self.err("group modifiers");
                }
                let alts = self.alts()?;
                if self.c.get(self.i) != Some(&')') {
                    return self.err("unclosed group");
                }
                self.i += 1;
                Ok(Atom::Group(alts))
            }
            '[' => self.class(),
            '\\' => self.escaped().map(Atom::Char),
            '.' | '*' | '+' | '?' | '{' | '}' | ']' => self.err("unsupported metacharacter"),
            c => Ok(Atom::Char(c)),
        }
    }
    fn escaped(&mut self) -> Result<char, PatternError> {
        match self.c.get(self.i) {
            Some(&e) if ESCAPABLE.contains(e) => {
                self.i += 1;
                Ok(e)
            }
            _ => self.err("unsupported escape"),
        }
    }
    fn class(&mut self) -> Result<Atom, PatternError> {
        let negated = self.c.get(self.i) == Some(&'^');
        if negated {
            self.i += 1;
        }
        let mut ranges = Vec::new();
        loop {
            let ch = match self.c.get(self.i) {
                Some(&c) => c,
                None => return self.err("unclosed class"),
            };
            self.i += 1;
            if ch == ']' {
                break;
            }
            let lo = if ch == '\\' { self.escaped()? } else { ch };
            if self.c.get(self.i) == Some(&'-') && self.c.get(self.i + 1).is_some_and(|&c| c != ']') {
                self.i += 1;
                let hc = self.c[self.i];
                self.i += 1;
                let hi = if hc == '\\' { self.escaped()? } else { hc };
                if hi < lo {
                    return self.err("reversed range");
                }
                ranges.push((lo, hi));
            } else {
                ranges.push((lo, lo));
            }
        }
        Ok(Atom::Class(ranges, negated))
    }
    fn num(&mut self) -> Result<usize, PatternError> {
        let start = self.i;
        while self.c.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        if start == self.i {
            return self.err("expected number");
        }
        self.c[start..self.i].iter().collect::<String>().parse().or_else(|_| self.err("bad number"))
    }
    fn quant(&mut self) -> Result<(usize, usize), PatternError> {
        match self.c.get(self.i) {
            Some('*') => {
                self.i += 1;
                Ok((0, usize::MAX))
            }
            Some('+') => {
                self.i += 1;
                Ok((1, usize::MAX))
            }
            Some('?') => {
                self.i += 1;
                Ok((0, 1))
            }
            Some('{') => {
                self.i += 1;
                let min = self.num()?;
                let max = if self.c.get(self.i) == Some(&',') {
                    self.i += 1;
                    self.num()?
                } else {
                    min
                };
                if self.c.get(self.i) != Some(&'}') || max < min {
                    return self.err("bad quantifier");
                }
                self.i += 1;
                Ok((min, max))
            }
            _ => Ok((1, 1)),
        }
    }
}

impl Pattern {
    pub fn compile(src: &str) -> Result<Pattern, PatternError> {
        let mut p = P { c: src.chars().collect(), i: 0, src };
        let alts = p.alts()?;
        if p.i != p.c.len() {
            return p.err("unbalanced parenthesis");
        }
        Ok(Pattern { alts })
    }

    pub fn is_match(&self, input: &str) -> bool {
        let s: Vec<char> = input.chars().collect();
        (0..=s.len()).any(|start| self.alts.iter().any(|alt| seq(alt, 0, &s, start, &mut |_| true)))
    }
}

fn seq(items: &[Item], i: usize, s: &[char], pos: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
    if i == items.len() {
        return k(pos);
    }
    rep(items, i, 0, s, pos, k)
}

fn rep(items: &[Item], i: usize, count: usize, s: &[char], pos: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
    let item = &items[i];
    if count < item.max {
        let matched = atom(&item.atom, s, pos, &mut |p| {
            if p == pos && count >= item.min {
                return false; // zero-width iteration guard
            }
            rep(items, i, count + 1, s, p, k)
        });
        if matched {
            return true;
        }
    }
    count >= item.min && seq(items, i + 1, s, pos, k)
}

fn atom(a: &Atom, s: &[char], pos: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
    match a {
        Atom::Char(c) => s.get(pos) == Some(c) && k(pos + 1),
        Atom::Class(ranges, negated) => match s.get(pos) {
            Some(&c) => (ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi) != *negated) && k(pos + 1),
            None => false,
        },
        Atom::Start => pos == 0 && k(pos),
        Atom::End => pos == s.len() && k(pos),
        Atom::Group(alts) => alts.iter().any(|alt| seq(alt, 0, s, pos, k)),
    }
}

#[cfg(test)]
mod tests {
    use super::Pattern;

    #[test]
    fn schema_patterns() {
        let hex = Pattern::compile("^[0-9a-f]{64}$").unwrap();
        assert!(hex.is_match(&"a".repeat(64)));
        assert!(!hex.is_match(&"a".repeat(63)));
        assert!(!hex.is_match(&format!("{}\n", "a".repeat(64))));
        let sha = Pattern::compile("^([0-9a-f]{40}|[0-9a-f]{64})$").unwrap();
        assert!(sha.is_match(&"0".repeat(40)) && sha.is_match(&"0".repeat(64)) && !sha.is_match(&"0".repeat(50)));
        let eng = Pattern::compile("^[a-z][a-z0-9_-]{1,63}$").unwrap();
        assert!(eng.is_match("supreme_kernel") && !eng.is_match("supreme_kernel\n") && !eng.is_match("S"));
        let ts = Pattern::compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$").unwrap();
        assert!(ts.is_match("2026-11-25T12:00:00.000Z") && !ts.is_match("2026-11-25T12:00:00x000Z"));
        let semver = Pattern::compile("^(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})$").unwrap();
        assert!(semver.is_match("3.1.0") && !semver.is_match("01.0.0"));
        assert!(Pattern::compile("ab").unwrap().is_match("xaby"));
        for bad in ["\\d", ".", "(?:a)", "[a", "(a", "a{2,1}"] {
            assert!(Pattern::compile(bad).is_err(), "{bad}");
        }
    }
}
