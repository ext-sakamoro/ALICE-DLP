//! `Sensitivity` + `PiiKind` enums.

use core::fmt;

/// データの機密レベル.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sensitivity {
    /// 公開情報.
    Public,
    /// 社内限定.
    Internal,
    /// 機密.
    Confidential,
    /// 最高機密.
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

/// PII の種別.
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
