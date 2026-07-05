//! `ContentInspector` — 統合 API + バッチスキャン.

use std::collections::HashMap;

use crate::classifier::Classifier;
use crate::detect::ScanResult;
use crate::kinds::{PiiKind, Sensitivity};
use crate::policy::{PolicyEngine, PolicyEvaluation};
use crate::scanner::Scanner;

/// コンテンツ検査器. スキャン、分類、ポリシー評価を統合する.
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

    /// テキストを検査し、スキャン結果を返す.
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

    /// テキストを検査し、ポリシー評価結果も含めて返す.
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

/// 複数テキストの一括スキャン結果.
#[derive(Debug, Clone)]
pub struct BatchScanResult {
    pub results: Vec<(usize, ScanResult)>,
    pub total_pii_count: usize,
    pub highest_sensitivity: Sensitivity,
    pub pii_summary: HashMap<PiiKind, usize>,
}

/// 複数テキストを一括スキャンする.
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
