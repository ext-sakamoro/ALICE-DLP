#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

//! ALICE-DLP: Data Loss Prevention
//!
//! PII検出、データ分類、マスキング/リダクション、ポリシーエンジンを提供する。

pub mod classifier;
pub mod detect;
pub mod inspector;
pub mod kinds;
pub mod masker;
pub mod policy;
pub mod prelude;
pub mod scanner;

#[cfg(test)]
mod integration_tests;

// Backward-compat re-exports.
pub use crate::classifier::*;
pub use crate::detect::*;
pub use crate::inspector::*;
pub use crate::kinds::*;
pub use crate::masker::*;
pub use crate::policy::*;
pub use crate::scanner::*;
