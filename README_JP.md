[English](README.md) | **日本語**

# ALICE-DLP

ALICEエコシステムのデータ損失防止 (DLP) モジュール。PII検出、データ分類、マスキング、ポリシーエンジンを外部依存なしの純Rustで提供。

## 概要

| 項目 | 値 |
|------|-----|
| **クレート名** | `alice-dlp` |
| **バージョン** | 1.0.0 |
| **ライセンス** | AGPL-3.0 |
| **エディション** | 2021 |

## 機能

- **PII検出** — メール、電話番号、クレジットカード番号、SSNを手書きパターンマッチャーで識別（regexクレート不使用）
- **データ分類** — Public / Internal / Confidential / Restricted の機密レベルを割り当て
- **マスキング・リダクション** — 文書構造を保持しつつ、検出されたPIIを置換・マスク
- **ポリシーエンジン** — 設定可能なルールでデータ取扱ポリシーを定義・評価
- **スキャン結果** — マッチ位置、PII種別、ポリシー違反を含む構造化出力

## アーキテクチャ

```
alice-dlp (lib.rs — 単一ファイルクレート)
├── Sensitivity               # データ分類レベル
├── PiiKind                    # PII種別列挙型
├── PiiMatch / ScanResult      # 位置付き検出結果
├── パターンヘルパー            # 手書きマッチャー（regex依存なし）
├── Policy / PolicyEngine      # ルール定義と評価
└── DlpScanner                 # トップレベルスキャナー
```

## クイックスタート

```rust
use alice_dlp::DlpScanner;

let scanner = DlpScanner::new();
let result = scanner.scan("Contact me at alice@example.com or 555-0123");
assert!(result.has_pii());
println!("Found {} PII matches", result.count());
```

## ビルド

```bash
cargo build
cargo test
cargo clippy -- -W clippy::all
```

## ライセンス

`AGPL-3.0 OR LicenseRef-Commercial` — デュアルライセンス どちらかを選べる

| 選択肢 | 条文 | こういう時 |
|--------|------|-----------|
| **AGPL-3.0** | [LICENSE-AGPL](LICENSE-AGPL) — 無償、報告義務なし | 自分の project も AGPL 互換の OSS、または社内利用のみ |
| **商用ライセンス** | [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) — 有償、コピーレフト義務を解除 | クローズドソース製品 / 商用 SaaS / エッジ・ファームウェア配布 / plugin 再配布 / ソース開示を禁じるプラットフォーム NDA |

AGPL は強いコピーレフト: `alice-dlp` を link して配布 / 提供する製品・ファームウェア・
サービスは AGPL で公開する義務がある これはオープンなエコシステムのための意図的な
選択で、それが実行できない場合のために商用ライセンスを用意している

商用ライセンスの問い合わせ: <contact@extoria.co.jp>
