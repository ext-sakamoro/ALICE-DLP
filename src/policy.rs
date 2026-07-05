//! `PolicyAction` + `PolicyRule` + `PolicyEngine` + `PolicyEvaluation`.

use crate::detect::PiiMatch;
use crate::kinds::{PiiKind, Sensitivity};

/// ポリシーアクション.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// 許可.
    Allow,
    /// 警告のみ.
    Warn,
    /// ブロック.
    Block,
    /// マスキングして許可.
    MaskAndAllow,
}

/// ポリシールール.
#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub name: String,
    pub description: String,
    pub min_sensitivity: Sensitivity,
    pub blocked_pii_kinds: Vec<PiiKind>,
    pub action: PolicyAction,
}

/// ポリシーエンジン.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

/// ポリシー評価結果.
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

    /// ルールを追加する.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// スキャン結果に対してポリシーを評価する.
    #[must_use]
    pub fn evaluate(&self, sensitivity: Sensitivity, pii_matches: &[PiiMatch]) -> PolicyEvaluation {
        let mut action = PolicyAction::Allow;
        let mut violated_rules = Vec::new();
        let mut warnings = Vec::new();

        let pii_kinds: Vec<PiiKind> = pii_matches.iter().map(|m| m.kind).collect();

        for rule in &self.rules {
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
