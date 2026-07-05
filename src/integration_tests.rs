//! Cross-module integration tests.

#![allow(
    clippy::doc_markdown,
    clippy::assertions_on_constants,
    clippy::suboptimal_flops,
    clippy::unreadable_literal,
    clippy::float_cmp
)]

use crate::classifier::*;
use crate::detect::{
    extract_digits, find_credit_cards, find_emails, find_phones, find_ssns, is_card_prefix,
    luhn_check, PiiMatch, ScanResult,
};
use crate::inspector::*;
use crate::kinds::*;
use crate::masker::*;
use crate::policy::*;
use crate::scanner::*;

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
    let matches = find_credit_cards("5500000000000004");
    assert_eq!(matches.len(), 1);
}

#[test]
fn detect_amex() {
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
    let inspector = ContentInspector::new(Scanner::new(), Classifier::new(), PolicyEngine::new());
    let result = inspector.inspect("Hello world");
    assert!(!result.has_pii());
    assert_eq!(result.sensitivity, Sensitivity::Public);
}

#[test]
fn inspector_detects_email() {
    let inspector = ContentInspector::new(Scanner::new(), Classifier::new(), PolicyEngine::new());
    let result = inspector.inspect("Contact admin@company.com");
    assert!(result.has_pii());
    assert_eq!(result.count(), 1);
}

#[test]
fn inspector_classifies_and_detects() {
    let inspector = ContentInspector::new(Scanner::new(), Classifier::new(), PolicyEngine::new());
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
    let inspector = ContentInspector::new(Scanner::new(), Classifier::new(), PolicyEngine::new());
    let texts = vec!["email: a@b.com", "clean text", "SSN: 123-45-6789"];
    let batch = batch_scan(&inspector, &texts);
    assert_eq!(batch.results.len(), 3);
    assert!(batch.total_pii_count >= 2);
    assert_eq!(batch.highest_sensitivity, Sensitivity::Public);
}

#[test]
fn batch_scan_empty() {
    let inspector = ContentInspector::new(Scanner::new(), Classifier::new(), PolicyEngine::new());
    let batch = batch_scan(&inspector, &[]);
    assert!(batch.results.is_empty());
    assert_eq!(batch.total_pii_count, 0);
}

#[test]
fn batch_scan_sensitivity_aggregation() {
    let inspector = ContentInspector::new(Scanner::new(), Classifier::new(), PolicyEngine::new());
    let texts = vec!["public text", "top secret data"];
    let batch = batch_scan(&inspector, &texts);
    assert_eq!(batch.highest_sensitivity, Sensitivity::Restricted);
}

#[test]
fn batch_scan_pii_summary() {
    let inspector = ContentInspector::new(Scanner::new(), Classifier::new(), PolicyEngine::new());
    let texts = vec!["a@b.com", "c@d.org"];
    let batch = batch_scan(&inspector, &texts);
    assert_eq!(*batch.pii_summary.get(&PiiKind::Email).unwrap_or(&0), 2);
}

// === Integration ===

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
