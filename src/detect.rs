//! PII 検出パターン (`PiiMatch`, `ScanResult`, 検出ヘルパー).

use crate::kinds::{PiiKind, Sensitivity};

/// 検出された PII の位置と種別.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiiMatch {
    pub kind: PiiKind,
    pub start: usize,
    pub end: usize,
    pub matched: String,
}

/// スキャン結果.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub matches: Vec<PiiMatch>,
    pub sensitivity: Sensitivity,
    pub policy_violations: Vec<String>,
}

impl ScanResult {
    #[must_use]
    pub const fn has_pii(&self) -> bool {
        !self.matches.is_empty()
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.matches.len()
    }

    #[must_use]
    pub const fn has_violations(&self) -> bool {
        !self.policy_violations.is_empty()
    }
}

const fn is_email_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '+' || c == '-'
}

const fn is_domain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-'
}

/// メールアドレスを検出する.
pub(crate) fn find_emails(text: &str) -> Vec<PiiMatch> {
    let mut results = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == '@' {
            let mut local_start = i;
            while local_start > 0 && is_email_char(chars[local_start - 1]) {
                local_start -= 1;
            }
            let mut domain_end = i + 1;
            while domain_end < len && is_domain_char(chars[domain_end]) {
                domain_end += 1;
            }
            if local_start < i && domain_end > i + 1 {
                let domain_part: String = chars[i + 1..domain_end].iter().collect();
                if domain_part.contains('.')
                    && !domain_part.starts_with('.')
                    && !domain_part.ends_with('.')
                {
                    let byte_start = chars[..local_start]
                        .iter()
                        .map(|c| c.len_utf8())
                        .sum::<usize>();
                    let byte_end = chars[..domain_end]
                        .iter()
                        .map(|c| c.len_utf8())
                        .sum::<usize>();
                    let matched: String = chars[local_start..domain_end].iter().collect();
                    results.push(PiiMatch {
                        kind: PiiKind::Email,
                        start: byte_start,
                        end: byte_end,
                        matched,
                    });
                    i = domain_end;
                    continue;
                }
            }
        }
        i += 1;
    }
    results
}

/// 連続する数字列を抽出するヘルパー.
pub(crate) fn extract_digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

/// Luhn アルゴリズムによるクレジットカード番号検証.
pub(crate) fn luhn_check(digits: &str) -> bool {
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum: u32 = 0;
    let mut double = false;
    for c in digits.chars().rev() {
        let Some(mut d) = c.to_digit(10) else {
            return false;
        };
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// クレジットカード番号を検出する (ハイフン/スペース区切り対応).
pub(crate) fn find_credit_cards(text: &str) -> Vec<PiiMatch> {
    let mut results = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if !chars[i].is_ascii_digit() {
            i += 1;
            continue;
        }

        let start = i;
        let mut j = i;
        let mut digit_count = 0;
        while j < len && (chars[j].is_ascii_digit() || chars[j] == '-' || chars[j] == ' ') {
            if chars[j].is_ascii_digit() {
                digit_count += 1;
            }
            j += 1;
            if digit_count >= 19 {
                break;
            }
        }
        if (13..=19).contains(&digit_count) {
            let candidate: String = chars[start..j].iter().collect();
            let digits = extract_digits(&candidate);
            if luhn_check(&digits) && is_card_prefix(&digits) {
                let byte_start = chars[..start].iter().map(|c| c.len_utf8()).sum::<usize>();
                let trimmed_end = candidate.trim_end_matches(|c: char| !c.is_ascii_digit());
                let actual_byte_end = byte_start + trimmed_end.len();
                results.push(PiiMatch {
                    kind: PiiKind::CreditCard,
                    start: byte_start,
                    end: actual_byte_end,
                    matched: trimmed_end.to_string(),
                });
                i = j;
                continue;
            }
        }
        i += 1;
    }
    results
}

/// カード番号の先頭がVisa/Mastercard/Amex/Discoverに該当するか.
pub(crate) fn is_card_prefix(digits: &str) -> bool {
    if digits.starts_with('4') {
        return true;
    }
    if digits.len() >= 2 {
        let prefix2: u32 = digits[..2].parse().unwrap_or(0);
        if (51..=55).contains(&prefix2) {
            return true;
        }
        if prefix2 == 34 || prefix2 == 37 {
            return true;
        }
    }
    if digits.starts_with("6011") || digits.starts_with("65") {
        return true;
    }
    false
}

/// 電話番号を検出する (米国形式).
pub(crate) fn find_phones(text: &str) -> Vec<PiiMatch> {
    let mut results = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == '+' || chars[i] == '(' || chars[i].is_ascii_digit() {
            let start = i;
            let mut j = i;
            let mut digit_count = 0;

            if j < len && chars[j] == '+' {
                j += 1;
            }

            while j < len
                && (chars[j].is_ascii_digit()
                    || chars[j] == '-'
                    || chars[j] == ' '
                    || chars[j] == '('
                    || chars[j] == ')'
                    || chars[j] == '.')
            {
                if chars[j].is_ascii_digit() {
                    digit_count += 1;
                }
                j += 1;
                if digit_count >= 15 {
                    break;
                }
            }

            if (10..=15).contains(&digit_count) {
                let candidate: String = chars[start..j].iter().collect();
                let trimmed = candidate.trim_end_matches(|c: char| !c.is_ascii_digit());
                if !trimmed.is_empty() {
                    let digits = extract_digits(trimmed);
                    if digits.len() >= 10 && digits.len() <= 11 {
                        let byte_start = chars[..start].iter().map(|c| c.len_utf8()).sum::<usize>();
                        let byte_end = byte_start + trimmed.len();
                        results.push(PiiMatch {
                            kind: PiiKind::Phone,
                            start: byte_start,
                            end: byte_end,
                            matched: trimmed.to_string(),
                        });
                        i = start + trimmed.chars().count();
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    results
}

/// SSN を検出する (xxx-xx-xxxx 形式).
pub(crate) fn find_ssns(text: &str) -> Vec<PiiMatch> {
    let mut results = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i + 10 < len {
        if chars[i].is_ascii_digit()
            && chars[i + 1].is_ascii_digit()
            && chars[i + 2].is_ascii_digit()
            && chars[i + 3] == '-'
            && chars[i + 4].is_ascii_digit()
            && chars[i + 5].is_ascii_digit()
            && chars[i + 6] == '-'
            && chars[i + 7].is_ascii_digit()
            && chars[i + 8].is_ascii_digit()
            && chars[i + 9].is_ascii_digit()
            && chars[i + 10].is_ascii_digit()
        {
            let before_ok = i == 0 || !chars[i - 1].is_ascii_digit();
            let after_ok = i + 11 >= len || !chars[i + 11].is_ascii_digit();
            if before_ok && after_ok {
                let matched: String = chars[i..i + 11].iter().collect();
                let area: u32 = matched[..3].parse().unwrap_or(0);
                let group: u32 = matched[4..6].parse().unwrap_or(0);
                let serial: u32 = matched[7..11].parse().unwrap_or(0);
                if area != 0 && area != 666 && area < 900 && group != 0 && serial != 0 {
                    let byte_start = chars[..i].iter().map(|c| c.len_utf8()).sum::<usize>();
                    let byte_end = byte_start + 11;
                    results.push(PiiMatch {
                        kind: PiiKind::Ssn,
                        start: byte_start,
                        end: byte_end,
                        matched,
                    });
                    i += 11;
                    continue;
                }
            }
        }
        i += 1;
    }
    results
}
