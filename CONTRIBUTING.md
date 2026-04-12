# Contributing to Misogi

Thank you for your interest in contributing to Misogi! This document provides guidelines and instructions for contributing to the project.

## 🌐 Language / 言語

This project supports both English and Japanese. Feel free to communicate in either language.

このプロジェクトは英語と日本語の両方に対応しています。どちらの言語でもご自由にご利用ください。

- [English Version](#contributing-to-misogi)
- [日本語版](#misogi-へのコントリビュート)

---

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* **Use a clear and descriptive title**
* **Describe the exact steps to reproduce the problem**
* **Provide specific examples to demonstrate the steps**
* **Describe the behavior you observed and what behavior you expected**
* **Include error messages and stack traces if applicable**
* **Include system information (OS, Rust version, etc.)**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* **Use a clear and descriptive title**
* **Provide a detailed description of the suggested enhancement**
* **Explain why this enhancement would be useful**
* **List some examples of how this enhancement would be used**

### Pull Requests

* Fill in the required template
* Follow the code style guidelines
* Include comments in your code where necessary
* Update documentation if needed
* Test your changes thoroughly
* Ensure all tests pass

---

## Code Style Guidelines

### Rust Code Style

* Use `rustfmt` for consistent formatting
* Follow Rust API Guidelines
* Use meaningful variable and function names
* Add comprehensive documentation comments
* Handle errors appropriately using `Result` and `Option`
* Write tests for new functionality

### Documentation Style

* All code comments must be in English
* Follow Japanese-style detailed documentation format
* Use Rust 2024 Edition standards
* Include examples in documentation where helpful

### Example

```rust
/// Transfers a file chunk to the receiver.
/// 
/// This function handles the core logic of chunked file transfer,
/// ensuring data integrity and proper error handling.
/// 
/// # Arguments
/// 
/// * `chunk_data` - A byte slice containing the chunk data
/// * `chunk_index` - The index of the chunk in the file
/// * `total_chunks` - Total number of chunks in the file
/// 
/// # Returns
/// 
/// * `Ok(())` if the transfer was successful
/// * `Err(TransferError)` if an error occurred
/// 
/// # Examples
/// 
/// ```
/// let chunk = vec![0u8; 1024];
/// transfer_chunk(chunk, 0, 10).await?;
/// ```
pub async fn transfer_chunk(
    chunk_data: &[u8],
    chunk_index: usize,
    total_chunks: usize,
) -> Result<(), TransferError> {
    // Implementation
}
```

---

## Development Setup

### Prerequisites

* Rust 1.75+ (Edition 2024)
* Git
* Protocol Buffers compiler

### Setting Up Development Environment

1. **Fork the repository**
   ```bash
   git clone https://github.com/your-username/Misogi.git
   cd Misogi
   ```

2. **Install dependencies**
   ```bash
   cargo build
   ```

3. **Run tests**
   ```bash
   cargo test
   ```

4. **Format code**
   ```bash
   cargo fmt
   ```

5. **Run clippy for linting**
   ```bash
   cargo clippy
   ```

---

## Commit Message Guidelines

We follow conventional commit format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

* `feat`: A new feature
* `fix`: A bug fix
* `docs`: Documentation changes
* `style`: Code style changes (formatting, etc.)
* `refactor`: Code refactoring
* `test`: Adding tests
* `chore`: Maintenance tasks

### Example

```
feat(sender): add chunked file transfer support

Implemented chunked file transfer with configurable chunk sizes.
This allows efficient transfer of large files with progress tracking.

Closes #123
```

---

## Code of Conduct

Please note that this project is released with a [Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

---

## Core Non-Compromise Principle / コアの不妥協原則

`misogi-core` is the sacred heart of Misogi. Its purity must be guarded like a shrine boundary.

### Immutable Rules（不変のルール）

| Rule | Reason |
|------|--------|
| **NO unnecessary `.clone()`** | Memory copies kill throughput. Use `&Cow`, `Arc`, references, or zero-copy APIs. |
| **NO country-specific business logic hardcoded in Core** | Japanese fiscal year rules, JP-specific PII patterns → `crates/misogi-core/contrib/jp/` or external plugins only. |
| **ALL business logic MUST be pluggable** | Use trait objects (`dyn Trait`), WASM plugins, or extension crates. Core stays minimal. |
| **Core crate dependency ceiling: 15 crates** | If you need a new dep, justify it in an Issue first. Maintainer approval required. |

### What Belongs in Core（Core に入っていいもの）

- Protocol definitions (protobuf)
- Hash utilities
- Error types
- Generic traits (Scanner, Sanitizer)
- Zero-copy data structures
- State machine primitives

### What Does NOT Belong（Core に入っちゃダメなもの）

- Country-specific date formats (→ `contrib/`)
- Industry-specific validation (→ plugins/WASM)
- UI or CLI logic (→ `misogi-sender`, `misogi-receiver`)
- Database adapters (→ feature-gated optional deps)

---

## License

By contributing to Misogi, you agree that your contributions will be licensed under the Apache 2.0 License.

---

# Misogi へのコントリビュート

Misogi プロジェクトに興味を持っていただき、ありがとうございます！このドキュメントでは、プロジェクトへのコントリビュートに関するガイドラインと手順を説明します。

## コントリビュート方法

### バグの報告

バグレポートを作成する前に、既存のイシューをご確認ください。すでに報告されている可能性があります。バグレポートを作成する際は、可能な限り多くの詳細を含めてください：

* **明確で説明的なタイトルを使用する**
* **問題を再現する正確な手順を説明する**
* **手順を実証する具体的な例を提供する**
* **観察された動作と期待される動作を説明する**
* **該当する場合はエラーメッセージとスタックトレースを含める**
* **システム情報（OS、Rust バージョンなど）を含める**

### 機能改善の提案

機能改善の提案は GitHub イシューとしてトラッキングされます。提案を作成する際は、以下を含めてください：

* **明確で説明的なタイトルを使用する**
* **提案する機能改善の詳細な説明を提供する**
* **この機能改善がなぜ有用かを説明する**
* **この機能改善がどのように使用されるかの例をリストする**

### プルリクエスト

* 必須のテンプレートを記入する
* コードスタイルガイドラインに従う
* 必要な場所にコードコメントを含める
* 必要に応じてドキュメントを更新する
* 変更を十分にテストする
* すべてのテストに合格することを確認する

---

## コードスタイルガイドライン

### Rust コードスタイル

* 一貫したフォーマットのために `rustfmt` を使用する
* Rust API ガイドラインに従う
* 意味のある変数名と関数名を使用する
* 包括的なドキュメントコメントを追加する
* `Result` と `Option` を使用して適切にエラーを処理する
* 新しい機能のテストを書く

### ドキュメントスタイル

* すべてのコードコメントは英語であること
* 日本式の詳細ドキュメント形式に従う
* Rust 2024 Edition 標準を使用する
* 役立つ場合はドキュメントに例を含める

---

## 開発セットアップ

### 前提条件

* Rust 1.75+ (Edition 2024)
* Git
* Protocol Buffers コンパイラ

### 開発環境のセットアップ

1. **リポジトリをフォーク**
   ```bash
   git clone https://github.com/your-username/Misogi.git
   cd Misogi
   ```

2. **依存関係のインストール**
   ```bash
   cargo build
   ```

3. **テストの実行**
   ```bash
   cargo test
   ```

4. **コードのフォーマット**
   ```bash
   cargo fmt
   ```

5. **リンティングの実行**
   ```bash
   cargo clippy
   ```

---

## コミットメッセージガイドライン

従来のコミット形式に従います：

```
<type>(<scope>): <subject>

<body>

<footer>
```

### タイプ

* `feat`: 新しい機能
* `fix`: バグ修正
* `docs`: ドキュメント変更
* `style`: コードスタイル変更（フォーマットなど）
* `refactor`: コードのリファクタリング
* `test`: テストの追加
* `chore`: メンテナンスタスク

---

## コアの不妥協原則（Core Non-Compromise Principle）

`misogi-core` は Misogi の神髄です。その純潔性は結界のように守られなければなりません。

### 不変のルール

| ルール | 理由 |
|--------|------|
| **不必要な `.clone()` を禁止** | メモリコピーはスループットを殺します。`&Cow`、`Arc`、参照、ゼロコピ API を使用してください。 |
| **国固有の業務ロジックを Core にハードコード禁止** | 日本の会計年度ルール、JP 固有の PII パターン → `crates/misogi-core/contrib/jp/` または外部プラグインのみ。 |
| **全ての業務ロジックはプラガブル必須** | trait オブジェクト (`dyn Trait`)、WASM プラグイン、拡張クレートを使用。Core は極限まで軽量に。 |
| **Core crate 依存数上限: 15** | 新規依存が必要な場合は Issue で理由を説明し、メンテナ承認が必要。 |

### Core に入っていいもの

- プロトコル定義 (protobuf)
- ハッシュユーティリティ
- エラー型
- 汎用トレイト (Scanner, Sanitizer)
- ゼロコピデータ構造
- ステートマシンプリミティブ

### Core に入っちゃダメなもの

- 国固有の日付フォーマット (→ `contrib/`)
- 業種固有のバリデーション (→ プラグイン/WASM)
- UI や CLI ロジック (→ `misogi-sender`, `misogi-receiver`)
- データベースアダプタ (→ feature-gated なオプション依存)

---

## 行動規範

このプロジェクトには [行動規範](CODE_OF_CONDUCT_ja.md) が設定されています。このプロジェクトに参加することで、その規約に従うことに同意したことになります。

---

## ライセンス

Misogi にコントリビュートすることにより、あなたのコントリビューションが Apache 2.0 ライセンスの下でライセンスされることに同意したことになります。
