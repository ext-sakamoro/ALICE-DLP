**English** | [日本語](README_JP.md)

# ALICE-DLP

Data Loss Prevention module for the ALICE ecosystem. Detects PII, classifies data sensitivity, masks sensitive content, and enforces policies -- all in pure Rust with zero external dependencies.

## Overview

| Item | Value |
|------|-------|
| **Crate** | `alice-dlp` |
| **Version** | 1.0.0 |
| **License** | AGPL-3.0 |
| **Edition** | 2021 |

## Features

- **PII Detection** — Identify emails, phone numbers, credit card numbers, and SSNs via hand-written pattern matchers (no regex crate)
- **Data Classification** — Assign sensitivity levels: Public, Internal, Confidential, Restricted
- **Masking & Redaction** — Replace or mask detected PII in text while preserving document structure
- **Policy Engine** — Define and evaluate data handling policies with configurable rules
- **Scan Results** — Structured output with match positions, PII kind, and policy violations

## Architecture

```
alice-dlp (lib.rs — single-file crate)
├── Sensitivity               # Data classification levels
├── PiiKind                    # PII type enum (Email, Phone, CreditCard, SSN)
├── PiiMatch / ScanResult      # Detection results with positions
├── Pattern helpers            # Hand-rolled matchers (no regex dep)
├── Policy / PolicyEngine      # Rule definition and evaluation
└── DlpScanner                 # Top-level scanner orchestrator
```

## Quick Start

```rust
use alice_dlp::DlpScanner;

let scanner = DlpScanner::new();
let result = scanner.scan("Contact me at alice@example.com or 555-0123");
assert!(result.has_pii());
println!("Found {} PII matches", result.count());
```

## Build

```bash
cargo build
cargo test
cargo clippy -- -W clippy::all
```

## License

AGPL-3.0 -- see [LICENSE](LICENSE) for details.
