//! `Scanner` — PII 検出パイプライン.

use crate::detect::{find_credit_cards, find_emails, find_phones, find_ssns, PiiMatch};

/// PII スキャナー. テキストから PII を検出する.
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

    /// テキストをスキャンし、PII を検出する.
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
