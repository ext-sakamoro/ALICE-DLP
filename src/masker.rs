//! `MaskStrategy` + `Masker` — PII マスキング.

use crate::detect::PiiMatch;

/// マスキング戦略.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskStrategy {
    /// 全体を固定文字に置換: `****`
    Full,
    /// 末尾 N 文字のみ表示: `***1234`
    PartialRevealLast(usize),
    /// カスタム置換文字列の文字を使用.
    CustomChar(char),
    /// `[REDACTED]` に置換.
    Redact,
}

/// PII マスカー.
#[derive(Debug, Clone)]
pub struct Masker {
    pub(crate) strategy: MaskStrategy,
}

impl Masker {
    #[must_use]
    pub const fn new(strategy: MaskStrategy) -> Self {
        Self { strategy }
    }

    /// テキスト中の検出済み PII をマスキングする.
    #[must_use]
    pub fn mask(&self, text: &str, matches: &[PiiMatch]) -> String {
        if matches.is_empty() {
            return text.to_string();
        }

        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;

        for m in matches {
            if m.start > last_end {
                result.push_str(&text[last_end..m.start]);
            }
            result.push_str(&self.mask_value(&m.matched));
            last_end = m.end;
        }

        if last_end < text.len() {
            result.push_str(&text[last_end..]);
        }

        result
    }

    pub(crate) fn mask_value(&self, value: &str) -> String {
        let char_count = value.chars().count();
        match self.strategy {
            MaskStrategy::Full => "*".repeat(char_count),
            MaskStrategy::PartialRevealLast(n) => {
                if char_count <= n {
                    return value.to_string();
                }
                let masked_count = char_count - n;
                let mut s = "*".repeat(masked_count);
                s.extend(value.chars().skip(masked_count));
                s
            }
            MaskStrategy::CustomChar(c) => std::iter::repeat_n(c, char_count).collect(),
            MaskStrategy::Redact => "[REDACTED]".to_string(),
        }
    }
}

impl Default for Masker {
    fn default() -> Self {
        Self {
            strategy: MaskStrategy::Full,
        }
    }
}
