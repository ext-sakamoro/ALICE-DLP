#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

//! ALICE-DLP: Data Loss Prevention
//!
//! PII検出、データ分類、マスキング/リダクション、ポリシーエンジンを提供する。

use core::fmt;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Sensitivity / Classification
// ---------------------------------------------------------------------------

/// データの機密レベル。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sensitivity {
    /// 公開情報。
    Public,
    /// 社内限定。
    Internal,
    /// 機密。
    Confidential,
    /// 最高機密。
    Restricted,
}

impl fmt::Display for Sensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "Public"),
            Self::Internal => write!(f, "Internal"),
            Self::Confidential => write!(f, "Confidential"),
            Self::Restricted => write!(f, "Restricted"),
        }
    }
}

/// PII の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PiiKind {
    Email,
    Phone,
    CreditCard,
    Ssn,
}

impl fmt::Display for PiiKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Email => write!(f, "Email"),
            Self::Phone => write!(f, "Phone"),
            Self::CreditCard => write!(f, "CreditCard"),
            Self::Ssn => write!(f, "SSN"),
        }
    }
}

// ---------------------------------------------------------------------------
// Detection result
// ---------------------------------------------------------------------------

/// 検出された PII の位置と種別。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiiMatch {
    pub kind: PiiKind,
    pub start: usize,
    pub end: usize,
    pub matched: String,
}

/// スキャン結果。
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

// ---------------------------------------------------------------------------
// Pattern helpers (手動パターンマッチ — 外部依存なし)
// ---------------------------------------------------------------------------

const fn is_email_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '+' || c == '-'
}

const fn is_domain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-'
}

/// メールアドレスを検出する。
fn find_emails(text: &str) -> Vec<PiiMatch> {
    let mut results = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == '@' {
            // @ の前のローカルパートを遡る
            let mut local_start = i;
            while local_start > 0 && is_email_char(chars[local_start - 1]) {
                local_start -= 1;
            }
            // @ の後のドメインパートを進む
            let mut domain_end = i + 1;
            while domain_end < len && is_domain_char(chars[domain_end]) {
                domain_end += 1;
            }
            // 最低限の検証: local部1文字以上、ドメインにドットあり
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

/// 連続する数字列を抽出するヘルパー。
fn extract_digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

/// Luhn アルゴリズムによるクレジットカード番号検証。
fn luhn_check(digits: &str) -> bool {
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

/// クレジットカード番号を検出する（ハイフン/スペース区切り対応）。
fn find_credit_cards(text: &str) -> Vec<PiiMatch> {
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
        // 数字 + ハイフン/スペースの連続を取得
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
                // 末尾の非数字を除去
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

/// カード番号の先頭がVisa/Mastercard/Amex/Discoverに該当するか。
fn is_card_prefix(digits: &str) -> bool {
    if digits.starts_with('4') {
        return true; // Visa
    }
    if digits.len() >= 2 {
        let prefix2: u32 = digits[..2].parse().unwrap_or(0);
        if (51..=55).contains(&prefix2) {
            return true; // Mastercard
        }
        if prefix2 == 34 || prefix2 == 37 {
            return true; // Amex
        }
    }
    if digits.starts_with("6011") || digits.starts_with("65") {
        return true; // Discover
    }
    false
}

/// 電話番号を検出する（米国形式: xxx-xxx-xxxx, (xxx) xxx-xxxx, +1xxxxxxxxxx 等）。
fn find_phones(text: &str) -> Vec<PiiMatch> {
    let mut results = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // +1, (, または数字で始まるパターンを試行
        if chars[i] == '+' || chars[i] == '(' || chars[i].is_ascii_digit() {
            let start = i;
            let mut j = i;
            let mut digit_count = 0;

            // +1 プレフィックス
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
                    // カード番号との重複を避ける: 10-11桁のみ電話番号として扱う
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

/// SSN を検出する（xxx-xx-xxxx 形式）。
fn find_ssns(text: &str) -> Vec<PiiMatch> {
    let mut results = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i + 10 < len {
        // パターン: DDD-DD-DDDD
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
            // 前後が数字でないことを確認（部分一致を防ぐ）
            let before_ok = i == 0 || !chars[i - 1].is_ascii_digit();
            let after_ok = i + 11 >= len || !chars[i + 11].is_ascii_digit();
            if before_ok && after_ok {
                let matched: String = chars[i..i + 11].iter().collect();
                // 無効な SSN を除外 (000, 666, 900-999 area)
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

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/// PII スキャナー。テキストから PII を検出する。
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct Scanner {
    detect_email: bool,
    detect_phone: bool,
    detect_credit_card: bool,
    detect_ssn: bool,
}

impl Default for Scanner {
    fn default() -> Self {
        Self {
            detect_email: true,
            detect_phone: true,
            detect_credit_card: true,
            detect_ssn: true,
        }
    }
}

impl Scanner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_email(mut self, enabled: bool) -> Self {
        self.detect_email = enabled;
        self
    }

    #[must_use]
    pub const fn with_phone(mut self, enabled: bool) -> Self {
        self.detect_phone = enabled;
        self
    }

    #[must_use]
    pub const fn with_credit_card(mut self, enabled: bool) -> Self {
        self.detect_credit_card = enabled;
        self
    }

    #[must_use]
    pub const fn with_ssn(mut self, enabled: bool) -> Self {
        self.detect_ssn = enabled;
        self
    }

    /// テキストをスキャンし、PII を検出する。
    #[must_use]
    pub fn scan(&self, text: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();
        if self.detect_email {
            matches.extend(find_emails(text));
        }
        if self.detect_ssn {
            matches.extend(find_ssns(text));
        }
        if self.detect_credit_card {
            matches.extend(find_credit_cards(text));
        }
        if self.detect_phone {
            matches.extend(find_phones(text));
        }
        matches.sort_by_key(|m| m.start);
        matches
    }
}

// ---------------------------------------------------------------------------
// Masker
// ---------------------------------------------------------------------------

/// マスキング戦略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskStrategy {
    /// 全体を固定文字に置換: `****`
    Full,
    /// 末尾 N 文字のみ表示: `***1234`
    PartialRevealLast(usize),
    /// カスタム置換文字列の文字を使用。
    CustomChar(char),
    /// `[REDACTED]` に置換。
    Redact,
}

/// PII マスカー。
#[derive(Debug, Clone)]
pub struct Masker {
    strategy: MaskStrategy,
}

impl Masker {
    #[must_use]
    pub const fn new(strategy: MaskStrategy) -> Self {
        Self { strategy }
    }

    /// テキスト中の検出済み PII をマスキングする。
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

    fn mask_value(&self, value: &str) -> String {
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

// ---------------------------------------------------------------------------
// Data Classification
// ---------------------------------------------------------------------------

/// データ分類器。キーワードベースで機密レベルを判定する。
#[derive(Debug, Clone)]
pub struct Classifier {
    rules: Vec<ClassificationRule>,
}

/// 分類ルール。
#[derive(Debug, Clone)]
pub struct ClassificationRule {
    pub keywords: Vec<String>,
    pub sensitivity: Sensitivity,
}

impl Classifier {
    /// デフォルトの分類ルールで初期化。
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: vec![
                ClassificationRule {
                    keywords: vec![
                        "top secret".into(),
                        "classified".into(),
                        "restricted".into(),
                    ],
                    sensitivity: Sensitivity::Restricted,
                },
                ClassificationRule {
                    keywords: vec!["confidential".into(), "private".into(), "secret".into()],
                    sensitivity: Sensitivity::Confidential,
                },
                ClassificationRule {
                    keywords: vec![
                        "internal".into(),
                        "internal use only".into(),
                        "do not distribute".into(),
                    ],
                    sensitivity: Sensitivity::Internal,
                },
            ],
        }
    }

    /// カスタムルールを追加する。
    pub fn add_rule(&mut self, keywords: Vec<String>, sensitivity: Sensitivity) {
        self.rules.push(ClassificationRule {
            keywords,
            sensitivity,
        });
    }

    /// テキストの機密レベルを判定する。
    #[must_use]
    pub fn classify(&self, text: &str) -> Sensitivity {
        let lower = text.to_lowercase();
        let mut max_sensitivity = Sensitivity::Public;
        for rule in &self.rules {
            for keyword in &rule.keywords {
                if lower.contains(keyword) && rule.sensitivity > max_sensitivity {
                    max_sensitivity = rule.sensitivity;
                }
            }
        }
        max_sensitivity
    }
}

impl Default for Classifier {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Policy Engine
// ---------------------------------------------------------------------------

/// ポリシーアクション。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// 許可。
    Allow,
    /// 警告のみ。
    Warn,
    /// ブロック。
    Block,
    /// マスキングして許可。
    MaskAndAllow,
}

/// ポリシールール。
#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub name: String,
    pub description: String,
    pub min_sensitivity: Sensitivity,
    pub blocked_pii_kinds: Vec<PiiKind>,
    pub action: PolicyAction,
}

/// ポリシーエンジン。
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

/// ポリシー評価結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub action: PolicyAction,
    pub violated_rules: Vec<String>,
    pub warnings: Vec<String>,
}

impl PolicyEngine {
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// ルールを追加する。
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// スキャン結果に対してポリシーを評価する。
    #[must_use]
    pub fn evaluate(&self, sensitivity: Sensitivity, pii_matches: &[PiiMatch]) -> PolicyEvaluation {
        let mut action = PolicyAction::Allow;
        let mut violated_rules = Vec::new();
        let mut warnings = Vec::new();

        let pii_kinds: Vec<PiiKind> = pii_matches.iter().map(|m| m.kind).collect();

        for rule in &self.rules {
            // 機密レベルまたは PII 種別によるチェック
            let violated = sensitivity >= rule.min_sensitivity
                || rule
                    .blocked_pii_kinds
                    .iter()
                    .any(|blocked| pii_kinds.contains(blocked));

            if violated {
                match rule.action {
                    PolicyAction::Block => {
                        action = PolicyAction::Block;
                        violated_rules.push(rule.name.clone());
                    }
                    PolicyAction::Warn => {
                        if action != PolicyAction::Block {
                            action = PolicyAction::Warn;
                        }
                        warnings.push(format!("{}: {}", rule.name, rule.description));
                    }
                    PolicyAction::MaskAndAllow => {
                        if action == PolicyAction::Allow {
                            action = PolicyAction::MaskAndAllow;
                        }
                        violated_rules.push(rule.name.clone());
                    }
                    PolicyAction::Allow => {}
                }
            }
        }

        PolicyEvaluation {
            action,
            violated_rules,
            warnings,
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Content Inspector (統合 API)
// ---------------------------------------------------------------------------

/// コンテンツ検査器。スキャン、分類、ポリシー評価を統合する。
#[derive(Debug, Clone)]
pub struct ContentInspector {
    scanner: Scanner,
    classifier: Classifier,
    policy_engine: PolicyEngine,
}

impl ContentInspector {
    #[must_use]
    pub const fn new(
        scanner: Scanner,
        classifier: Classifier,
        policy_engine: PolicyEngine,
    ) -> Self {
        Self {
            scanner,
            classifier,
            policy_engine,
        }
    }

    /// テキストを検査し、スキャン結果を返す。
    #[must_use]
    pub fn inspect(&self, text: &str) -> ScanResult {
        let matches = self.scanner.scan(text);
        let sensitivity = self.classifier.classify(text);
        let evaluation = self.policy_engine.evaluate(sensitivity, &matches);

        ScanResult {
            matches,
            sensitivity,
            policy_violations: evaluation.violated_rules,
        }
    }

    /// テキストを検査し、ポリシー評価結果も含めて返す。
    #[must_use]
    pub fn inspect_with_policy(&self, text: &str) -> (ScanResult, PolicyEvaluation) {
        let matches = self.scanner.scan(text);
        let sensitivity = self.classifier.classify(text);
        let evaluation = self.policy_engine.evaluate(sensitivity, &matches);

        let result = ScanResult {
            matches,
            sensitivity,
            policy_violations: evaluation.violated_rules.clone(),
        };

        (result, evaluation)
    }
}

// ---------------------------------------------------------------------------
// Batch scanning
// ---------------------------------------------------------------------------

/// 複数テキストの一括スキャン結果。
#[derive(Debug, Clone)]
pub struct BatchScanResult {
    pub results: Vec<(usize, ScanResult)>,
    pub total_pii_count: usize,
    pub highest_sensitivity: Sensitivity,
    pub pii_summary: HashMap<PiiKind, usize>,
}

/// 複数テキストを一括スキャンする。
#[must_use]
pub fn batch_scan(inspector: &ContentInspector, texts: &[&str]) -> BatchScanResult {
    let mut results = Vec::new();
    let mut total_pii_count = 0;
    let mut highest_sensitivity = Sensitivity::Public;
    let mut pii_summary: HashMap<PiiKind, usize> = HashMap::new();

    for (idx, text) in texts.iter().enumerate() {
        let result = inspector.inspect(text);
        total_pii_count += result.matches.len();
        if result.sensitivity > highest_sensitivity {
            highest_sensitivity = result.sensitivity;
        }
        for m in &result.matches {
            *pii_summary.entry(m.kind).or_insert(0) += 1;
        }
        results.push((idx, result));
    }

    BatchScanResult {
        results,
        total_pii_count,
        highest_sensitivity,
        pii_summary,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // === Email detection ===

    #[test]
    fn detect_simple_email() {
        let matches = find_emails("contact user@example.com please");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched, "user@example.com");
        assert_eq!(matches[0].kind, PiiKind::Email);
    }

    #[test]
    fn detect_email_with_plus() {
        let matches = find_emails("send to user+tag@example.com");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched, "user+tag@example.com");
    }

    #[test]
    fn detect_email_with_dots() {
        let matches = find_emails("mail: first.last@sub.domain.co.jp");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched, "first.last@sub.domain.co.jp");
    }

    #[test]
    fn detect_multiple_emails() {
        let matches = find_emails("a@b.com and c@d.org");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn no_email_without_domain_dot() {
        let matches = find_emails("user@localhost");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn no_email_bare_at() {
        let matches = find_emails("@ something");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn email_at_start() {
        let matches = find_emails("test@foo.bar rest");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched, "test@foo.bar");
    }

    #[test]
    fn email_at_end() {
        let matches = find_emails("text me@example.org");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched, "me@example.org");
    }

    #[test]
    fn email_with_hyphen_domain() {
        let matches = find_emails("x@my-domain.com");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn no_email_domain_starts_dot() {
        let matches = find_emails("x@.bad.com");
        assert_eq!(matches.len(), 0);
    }

    // === SSN detection ===

    #[test]
    fn detect_ssn() {
        let matches = find_ssns("SSN: 123-45-6789");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched, "123-45-6789");
        assert_eq!(matches[0].kind, PiiKind::Ssn);
    }

    #[test]
    fn detect_multiple_ssns() {
        let matches = find_ssns("123-45-6789 and 234-56-7890");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn no_ssn_area_zero() {
        let matches = find_ssns("000-12-3456");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn no_ssn_area_666() {
        let matches = find_ssns("666-12-3456");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn no_ssn_area_900() {
        let matches = find_ssns("900-12-3456");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn no_ssn_group_zero() {
        let matches = find_ssns("123-00-4567");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn no_ssn_serial_zero() {
        let matches = find_ssns("123-45-0000");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn ssn_boundary_check() {
        // 前後に数字があるとSSNとみなさない
        let matches = find_ssns("1123-45-67890");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn ssn_at_text_start() {
        let matches = find_ssns("123-45-6789 is the number");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn ssn_at_text_end() {
        let matches = find_ssns("Number is 123-45-6789");
        assert_eq!(matches.len(), 1);
    }

    // === Credit card detection ===

    #[test]
    fn detect_visa_card() {
        let matches = find_credit_cards("card: 4111111111111111");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::CreditCard);
    }

    #[test]
    fn detect_visa_with_dashes() {
        let matches = find_credit_cards("4111-1111-1111-1111");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn detect_visa_with_spaces() {
        let matches = find_credit_cards("4111 1111 1111 1111");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn detect_mastercard() {
        // 5500 0000 0000 0004 は Luhn 有効
        let matches = find_credit_cards("5500000000000004");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn detect_amex() {
        // 3782 822463 10005 は Luhn 有効
        let matches = find_credit_cards("378282246310005");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn no_card_invalid_luhn() {
        let matches = find_credit_cards("4111111111111112");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn no_card_short_number() {
        let matches = find_credit_cards("411111111111");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn luhn_valid() {
        assert!(luhn_check("4111111111111111"));
    }

    #[test]
    fn luhn_invalid() {
        assert!(!luhn_check("4111111111111112"));
    }

    #[test]
    fn luhn_too_short() {
        assert!(!luhn_check("123"));
    }

    // === Phone detection ===

    #[test]
    fn detect_phone_dashes() {
        let matches = find_phones("call 555-123-4567 now");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Phone);
    }

    #[test]
    fn detect_phone_parens() {
        let matches = find_phones("(555) 123-4567");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn detect_phone_dots() {
        let matches = find_phones("555.123.4567");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn detect_phone_plus_one() {
        let matches = find_phones("+15551234567");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn no_phone_too_short() {
        let matches = find_phones("12345");
        assert_eq!(matches.len(), 0);
    }

    // === Scanner ===

    #[test]
    fn scanner_default_all_enabled() {
        let s = Scanner::new();
        let matches = s.scan("email: a@b.com SSN: 123-45-6789");
        assert!(matches.len() >= 2);
    }

    #[test]
    fn scanner_disable_email() {
        let s = Scanner::new().with_email(false);
        let matches = s.scan("a@b.com");
        assert!(matches.is_empty());
    }

    #[test]
    fn scanner_disable_ssn() {
        let s = Scanner::new().with_ssn(false);
        let matches = s.scan("123-45-6789");
        // SSN検出無効なので SSN としては検出されない
        let ssn_matches: Vec<_> = matches.iter().filter(|m| m.kind == PiiKind::Ssn).collect();
        assert!(ssn_matches.is_empty());
    }

    #[test]
    fn scanner_disable_credit_card() {
        let s = Scanner::new().with_credit_card(false);
        let matches = s.scan("4111111111111111");
        let cc_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::CreditCard)
            .collect();
        assert!(cc_matches.is_empty());
    }

    #[test]
    fn scanner_disable_phone() {
        let s = Scanner::new().with_phone(false);
        let matches = s.scan("555-123-4567");
        let phone_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::Phone)
            .collect();
        assert!(phone_matches.is_empty());
    }

    #[test]
    fn scanner_sorted_by_position() {
        let s = Scanner::new();
        let matches = s.scan("SSN 123-45-6789 email a@b.com");
        if matches.len() >= 2 {
            for w in matches.windows(2) {
                assert!(w[0].start <= w[1].start);
            }
        }
    }

    #[test]
    fn scanner_empty_text() {
        let s = Scanner::new();
        let matches = s.scan("");
        assert!(matches.is_empty());
    }

    #[test]
    fn scanner_no_pii() {
        let s = Scanner::new();
        let matches = s.scan("Hello world, this is a normal text.");
        assert!(matches.is_empty());
    }

    // === Masker ===

    #[test]
    fn mask_full() {
        let masker = Masker::new(MaskStrategy::Full);
        let matches = find_emails("user@example.com");
        let result = masker.mask("user@example.com", &matches);
        assert_eq!(result, "****************");
    }

    #[test]
    fn mask_partial_reveal() {
        let masker = Masker::new(MaskStrategy::PartialRevealLast(4));
        let matches = find_emails("user@example.com");
        let result = masker.mask("user@example.com", &matches);
        assert!(result.ends_with(".com"));
        assert!(result.starts_with('*'));
    }

    #[test]
    fn mask_custom_char() {
        let masker = Masker::new(MaskStrategy::CustomChar('#'));
        let matches = find_emails("a@b.com");
        let result = masker.mask("a@b.com", &matches);
        assert_eq!(result, "#######");
    }

    #[test]
    fn mask_redact() {
        let masker = Masker::new(MaskStrategy::Redact);
        let matches = find_emails("a@b.com");
        let result = masker.mask("a@b.com", &matches);
        assert_eq!(result, "[REDACTED]");
    }

    #[test]
    fn mask_no_matches() {
        let masker = Masker::new(MaskStrategy::Full);
        let result = masker.mask("hello", &[]);
        assert_eq!(result, "hello");
    }

    #[test]
    fn mask_preserves_surrounding() {
        let masker = Masker::new(MaskStrategy::Redact);
        let matches = find_emails("before a@b.com after");
        let result = masker.mask("before a@b.com after", &matches);
        assert_eq!(result, "before [REDACTED] after");
    }

    #[test]
    fn mask_multiple_pii() {
        let masker = Masker::new(MaskStrategy::Redact);
        let text = "emails: a@b.com and x@y.org";
        let matches = find_emails(text);
        let result = masker.mask(text, &matches);
        assert_eq!(result, "emails: [REDACTED] and [REDACTED]");
    }

    #[test]
    fn mask_ssn_full() {
        let masker = Masker::new(MaskStrategy::Full);
        let text = "SSN: 123-45-6789";
        let matches = find_ssns(text);
        let result = masker.mask(text, &matches);
        assert_eq!(result, "SSN: ***********");
    }

    #[test]
    fn masker_default() {
        let masker = Masker::default();
        assert_eq!(masker.strategy, MaskStrategy::Full);
    }

    #[test]
    fn mask_partial_short_value() {
        let masker = Masker::new(MaskStrategy::PartialRevealLast(100));
        let result = masker.mask_value("short");
        assert_eq!(result, "short");
    }

    // === Classifier ===

    #[test]
    fn classify_public() {
        let c = Classifier::new();
        assert_eq!(c.classify("Hello world"), Sensitivity::Public);
    }

    #[test]
    fn classify_internal() {
        let c = Classifier::new();
        assert_eq!(
            c.classify("Internal use only document"),
            Sensitivity::Internal
        );
    }

    #[test]
    fn classify_confidential() {
        let c = Classifier::new();
        assert_eq!(
            c.classify("This is confidential info"),
            Sensitivity::Confidential
        );
    }

    #[test]
    fn classify_restricted() {
        let c = Classifier::new();
        assert_eq!(
            c.classify("Top secret project plan"),
            Sensitivity::Restricted
        );
    }

    #[test]
    fn classify_case_insensitive() {
        let c = Classifier::new();
        assert_eq!(c.classify("TOP SECRET"), Sensitivity::Restricted);
    }

    #[test]
    fn classify_highest_wins() {
        let c = Classifier::new();
        // "internal" と "top secret" が両方あるとき Restricted が返る
        assert_eq!(
            c.classify("internal memo about top secret project"),
            Sensitivity::Restricted
        );
    }

    #[test]
    fn classify_custom_rule() {
        let mut c = Classifier::new();
        c.add_rule(vec!["salary".into()], Sensitivity::Restricted);
        assert_eq!(c.classify("salary report"), Sensitivity::Restricted);
    }

    #[test]
    fn classifier_default() {
        let c = Classifier::default();
        assert_eq!(c.classify("nothing special"), Sensitivity::Public);
    }

    // === Sensitivity ===

    #[test]
    fn sensitivity_ordering() {
        assert!(Sensitivity::Public < Sensitivity::Internal);
        assert!(Sensitivity::Internal < Sensitivity::Confidential);
        assert!(Sensitivity::Confidential < Sensitivity::Restricted);
    }

    #[test]
    fn sensitivity_display() {
        assert_eq!(Sensitivity::Public.to_string(), "Public");
        assert_eq!(Sensitivity::Internal.to_string(), "Internal");
        assert_eq!(Sensitivity::Confidential.to_string(), "Confidential");
        assert_eq!(Sensitivity::Restricted.to_string(), "Restricted");
    }

    #[test]
    fn sensitivity_eq() {
        assert_eq!(Sensitivity::Public, Sensitivity::Public);
        assert_ne!(Sensitivity::Public, Sensitivity::Internal);
    }

    #[test]
    fn sensitivity_clone() {
        let s = Sensitivity::Restricted;
        let s2 = s;
        assert_eq!(s, s2);
    }

    // === PiiKind ===

    #[test]
    fn pii_kind_display() {
        assert_eq!(PiiKind::Email.to_string(), "Email");
        assert_eq!(PiiKind::Phone.to_string(), "Phone");
        assert_eq!(PiiKind::CreditCard.to_string(), "CreditCard");
        assert_eq!(PiiKind::Ssn.to_string(), "SSN");
    }

    #[test]
    fn pii_kind_eq() {
        assert_eq!(PiiKind::Email, PiiKind::Email);
        assert_ne!(PiiKind::Email, PiiKind::Phone);
    }

    // === Policy Engine ===

    #[test]
    fn policy_allow_clean() {
        let engine = PolicyEngine::new();
        let eval = engine.evaluate(Sensitivity::Public, &[]);
        assert_eq!(eval.action, PolicyAction::Allow);
        assert!(eval.violated_rules.is_empty());
    }

    #[test]
    fn policy_block_on_ssn() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            name: "No SSN".into(),
            description: "SSN must not be transmitted".into(),
            min_sensitivity: Sensitivity::Restricted,
            blocked_pii_kinds: vec![PiiKind::Ssn],
            action: PolicyAction::Block,
        });
        let matches = vec![PiiMatch {
            kind: PiiKind::Ssn,
            start: 0,
            end: 11,
            matched: "123-45-6789".into(),
        }];
        let eval = engine.evaluate(Sensitivity::Public, &matches);
        assert_eq!(eval.action, PolicyAction::Block);
    }

    #[test]
    fn policy_warn_on_email() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            name: "Email Warning".into(),
            description: "Email detected".into(),
            min_sensitivity: Sensitivity::Restricted,
            blocked_pii_kinds: vec![PiiKind::Email],
            action: PolicyAction::Warn,
        });
        let matches = vec![PiiMatch {
            kind: PiiKind::Email,
            start: 0,
            end: 7,
            matched: "a@b.com".into(),
        }];
        let eval = engine.evaluate(Sensitivity::Public, &matches);
        assert_eq!(eval.action, PolicyAction::Warn);
        assert!(!eval.warnings.is_empty());
    }

    #[test]
    fn policy_block_overrides_warn() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            name: "Warn Email".into(),
            description: "warn".into(),
            min_sensitivity: Sensitivity::Restricted,
            blocked_pii_kinds: vec![PiiKind::Email],
            action: PolicyAction::Warn,
        });
        engine.add_rule(PolicyRule {
            name: "Block SSN".into(),
            description: "block".into(),
            min_sensitivity: Sensitivity::Restricted,
            blocked_pii_kinds: vec![PiiKind::Ssn],
            action: PolicyAction::Block,
        });
        let matches = vec![
            PiiMatch {
                kind: PiiKind::Email,
                start: 0,
                end: 7,
                matched: "a@b.com".into(),
            },
            PiiMatch {
                kind: PiiKind::Ssn,
                start: 10,
                end: 21,
                matched: "123-45-6789".into(),
            },
        ];
        let eval = engine.evaluate(Sensitivity::Public, &matches);
        assert_eq!(eval.action, PolicyAction::Block);
    }

    #[test]
    fn policy_mask_and_allow() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            name: "Mask CC".into(),
            description: "mask credit cards".into(),
            min_sensitivity: Sensitivity::Restricted,
            blocked_pii_kinds: vec![PiiKind::CreditCard],
            action: PolicyAction::MaskAndAllow,
        });
        let matches = vec![PiiMatch {
            kind: PiiKind::CreditCard,
            start: 0,
            end: 16,
            matched: "4111111111111111".into(),
        }];
        let eval = engine.evaluate(Sensitivity::Public, &matches);
        assert_eq!(eval.action, PolicyAction::MaskAndAllow);
    }

    #[test]
    fn policy_sensitivity_trigger() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            name: "High Sensitivity Block".into(),
            description: "block restricted content".into(),
            min_sensitivity: Sensitivity::Restricted,
            blocked_pii_kinds: vec![],
            action: PolicyAction::Block,
        });
        let eval = engine.evaluate(Sensitivity::Restricted, &[]);
        assert_eq!(eval.action, PolicyAction::Block);
    }

    #[test]
    fn policy_sensitivity_below_threshold() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            name: "High Only".into(),
            description: "restricted only".into(),
            min_sensitivity: Sensitivity::Restricted,
            blocked_pii_kinds: vec![],
            action: PolicyAction::Block,
        });
        // Confidential < Restricted なのでトリガーしない
        let eval = engine.evaluate(Sensitivity::Confidential, &[]);
        assert_eq!(eval.action, PolicyAction::Allow);
    }

    #[test]
    fn policy_default() {
        let engine = PolicyEngine::default();
        let eval = engine.evaluate(Sensitivity::Public, &[]);
        assert_eq!(eval.action, PolicyAction::Allow);
    }

    // === Content Inspector ===

    #[test]
    fn inspector_clean_text() {
        let inspector =
            ContentInspector::new(Scanner::new(), Classifier::new(), PolicyEngine::new());
        let result = inspector.inspect("Hello world");
        assert!(!result.has_pii());
        assert_eq!(result.sensitivity, Sensitivity::Public);
    }

    #[test]
    fn inspector_detects_email() {
        let inspector =
            ContentInspector::new(Scanner::new(), Classifier::new(), PolicyEngine::new());
        let result = inspector.inspect("Contact admin@company.com");
        assert!(result.has_pii());
        assert_eq!(result.count(), 1);
    }

    #[test]
    fn inspector_classifies_and_detects() {
        let inspector =
            ContentInspector::new(Scanner::new(), Classifier::new(), PolicyEngine::new());
        let result = inspector.inspect("Confidential: SSN 123-45-6789");
        assert!(result.has_pii());
        assert_eq!(result.sensitivity, Sensitivity::Confidential);
    }

    #[test]
    fn inspector_with_policy() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            name: "Block SSN".into(),
            description: "No SSN allowed".into(),
            min_sensitivity: Sensitivity::Restricted,
            blocked_pii_kinds: vec![PiiKind::Ssn],
            action: PolicyAction::Block,
        });
        let inspector = ContentInspector::new(Scanner::new(), Classifier::new(), engine);
        let (result, eval) = inspector.inspect_with_policy("SSN: 123-45-6789");
        assert!(result.has_pii());
        assert_eq!(eval.action, PolicyAction::Block);
        assert!(result.has_violations());
    }

    #[test]
    fn inspector_no_violations_clean() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            name: "Block SSN".into(),
            description: "No SSN".into(),
            min_sensitivity: Sensitivity::Restricted,
            blocked_pii_kinds: vec![PiiKind::Ssn],
            action: PolicyAction::Block,
        });
        let inspector = ContentInspector::new(Scanner::new(), Classifier::new(), engine);
        let result = inspector.inspect("No PII here");
        assert!(!result.has_violations());
    }

    // === ScanResult ===

    #[test]
    fn scan_result_has_pii() {
        let result = ScanResult {
            matches: vec![PiiMatch {
                kind: PiiKind::Email,
                start: 0,
                end: 7,
                matched: "a@b.com".into(),
            }],
            sensitivity: Sensitivity::Public,
            policy_violations: vec![],
        };
        assert!(result.has_pii());
        assert_eq!(result.count(), 1);
    }

    #[test]
    fn scan_result_no_pii() {
        let result = ScanResult {
            matches: vec![],
            sensitivity: Sensitivity::Public,
            policy_violations: vec![],
        };
        assert!(!result.has_pii());
        assert_eq!(result.count(), 0);
    }

    // === Batch scan ===

    #[test]
    fn batch_scan_multiple_texts() {
        let inspector =
            ContentInspector::new(Scanner::new(), Classifier::new(), PolicyEngine::new());
        let texts = vec!["email: a@b.com", "clean text", "SSN: 123-45-6789"];
        let batch = batch_scan(&inspector, &texts);
        assert_eq!(batch.results.len(), 3);
        assert!(batch.total_pii_count >= 2);
        assert_eq!(batch.highest_sensitivity, Sensitivity::Public);
    }

    #[test]
    fn batch_scan_empty() {
        let inspector =
            ContentInspector::new(Scanner::new(), Classifier::new(), PolicyEngine::new());
        let batch = batch_scan(&inspector, &[]);
        assert!(batch.results.is_empty());
        assert_eq!(batch.total_pii_count, 0);
    }

    #[test]
    fn batch_scan_sensitivity_aggregation() {
        let inspector =
            ContentInspector::new(Scanner::new(), Classifier::new(), PolicyEngine::new());
        let texts = vec!["public text", "top secret data"];
        let batch = batch_scan(&inspector, &texts);
        assert_eq!(batch.highest_sensitivity, Sensitivity::Restricted);
    }

    #[test]
    fn batch_scan_pii_summary() {
        let inspector =
            ContentInspector::new(Scanner::new(), Classifier::new(), PolicyEngine::new());
        let texts = vec!["a@b.com", "c@d.org"];
        let batch = batch_scan(&inspector, &texts);
        assert_eq!(*batch.pii_summary.get(&PiiKind::Email).unwrap_or(&0), 2);
    }

    // === Integration tests ===

    #[test]
    fn full_pipeline_mask_email() {
        let scanner = Scanner::new();
        let masker = Masker::new(MaskStrategy::Redact);
        let text = "Send to admin@corp.com for details";
        let matches = scanner.scan(text);
        let masked = masker.mask(text, &matches);
        assert!(!masked.contains("admin@corp.com"));
        assert!(masked.contains("[REDACTED]"));
    }

    #[test]
    fn full_pipeline_mask_ssn() {
        let scanner = Scanner::new();
        let masker = Masker::new(MaskStrategy::Full);
        let text = "SSN: 234-56-7890";
        let matches = scanner.scan(text);
        let masked = masker.mask(text, &matches);
        assert!(!masked.contains("234-56-7890"));
    }

    #[test]
    fn full_pipeline_classify_and_scan() {
        let scanner = Scanner::new();
        let classifier = Classifier::new();
        let text = "Confidential report: contact user@example.com";
        let matches = scanner.scan(text);
        let sensitivity = classifier.classify(text);
        assert!(!matches.is_empty());
        assert_eq!(sensitivity, Sensitivity::Confidential);
    }

    #[test]
    fn detect_discover_card() {
        let matches = find_credit_cards("6011111111111117");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn card_prefix_visa() {
        assert!(is_card_prefix("4111111111111111"));
    }

    #[test]
    fn card_prefix_mastercard() {
        assert!(is_card_prefix("5100000000000000"));
    }

    #[test]
    fn card_prefix_amex_34() {
        assert!(is_card_prefix("3400000000000000"));
    }

    #[test]
    fn card_prefix_amex_37() {
        assert!(is_card_prefix("3700000000000000"));
    }

    #[test]
    fn card_prefix_discover_6011() {
        assert!(is_card_prefix("6011000000000000"));
    }

    #[test]
    fn card_prefix_discover_65() {
        assert!(is_card_prefix("6500000000000000"));
    }

    #[test]
    fn card_prefix_invalid() {
        assert!(!is_card_prefix("9000000000000000"));
    }

    #[test]
    fn extract_digits_mixed() {
        assert_eq!(extract_digits("12-34 56"), "123456");
    }

    #[test]
    fn extract_digits_empty() {
        assert_eq!(extract_digits("abc"), "");
    }

    #[test]
    fn policy_evaluation_violated_rules_collected() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            name: "Rule A".into(),
            description: "desc A".into(),
            min_sensitivity: Sensitivity::Restricted,
            blocked_pii_kinds: vec![PiiKind::Email],
            action: PolicyAction::Block,
        });
        engine.add_rule(PolicyRule {
            name: "Rule B".into(),
            description: "desc B".into(),
            min_sensitivity: Sensitivity::Restricted,
            blocked_pii_kinds: vec![PiiKind::Ssn],
            action: PolicyAction::Block,
        });
        let matches = vec![
            PiiMatch {
                kind: PiiKind::Email,
                start: 0,
                end: 7,
                matched: "a@b.com".into(),
            },
            PiiMatch {
                kind: PiiKind::Ssn,
                start: 10,
                end: 21,
                matched: "123-45-6789".into(),
            },
        ];
        let eval = engine.evaluate(Sensitivity::Public, &matches);
        assert_eq!(eval.violated_rules.len(), 2);
    }

    #[test]
    fn mixed_pii_in_single_text() {
        let scanner = Scanner::new();
        let text = "Email a@b.com SSN 123-45-6789 Card 4111111111111111";
        let matches = scanner.scan(text);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::Ssn));
        assert!(kinds.contains(&PiiKind::CreditCard));
    }

    #[test]
    fn unicode_text_with_email() {
        let scanner = Scanner::new();
        let text = "Japanese text here and user@example.com";
        let matches = scanner.scan(text);
        let emails: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::Email)
            .collect();
        assert_eq!(emails.len(), 1);
    }

    #[test]
    fn pii_match_positions_correct() {
        let text = "abc user@example.com xyz";
        let matches = find_emails(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(&text[matches[0].start..matches[0].end], "user@example.com");
    }

    #[test]
    fn ssn_position_correct() {
        let text = "pre 123-45-6789 post";
        let matches = find_ssns(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(&text[matches[0].start..matches[0].end], "123-45-6789");
    }

    #[test]
    fn classifier_private_keyword() {
        let c = Classifier::new();
        assert_eq!(
            c.classify("This is private data"),
            Sensitivity::Confidential
        );
    }

    #[test]
    fn classifier_secret_keyword() {
        let c = Classifier::new();
        assert_eq!(
            c.classify("secret meeting notes"),
            Sensitivity::Confidential
        );
    }

    #[test]
    fn classifier_classified_keyword() {
        let c = Classifier::new();
        assert_eq!(c.classify("classified document"), Sensitivity::Restricted);
    }

    #[test]
    fn classifier_do_not_distribute() {
        let c = Classifier::new();
        assert_eq!(
            c.classify("do not distribute this memo"),
            Sensitivity::Internal
        );
    }
}
