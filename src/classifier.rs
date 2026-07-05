//! `Classifier` + `ClassificationRule` — キーワードベース分類.

use crate::kinds::Sensitivity;

/// データ分類器. キーワードベースで機密レベルを判定する.
#[derive(Debug, Clone)]
pub struct Classifier {
    rules: Vec<ClassificationRule>,
}

/// 分類ルール.
#[derive(Debug, Clone)]
pub struct ClassificationRule {
    pub keywords: Vec<String>,
    pub sensitivity: Sensitivity,
}

impl Classifier {
    /// デフォルトの分類ルールで初期化.
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

    /// カスタムルールを追加する.
    pub fn add_rule(&mut self, keywords: Vec<String>, sensitivity: Sensitivity) {
        self.rules.push(ClassificationRule {
            keywords,
            sensitivity,
        });
    }

    /// テキストの機密レベルを判定する.
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
