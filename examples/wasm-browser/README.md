# Misogi WASM Browser Demo

## ブラウザ内 WebAssembly によるファイルサニタイズ デモアプリケーション

Misogi CDR (Content Disarm and Reconstruction) パイプラインを WebAssembly でコンパイルし、ブラウザ上で動作する完全なデモページです。サーバー側処理なしで、PDF および Office ドキュメントのサニタイズ、個人情報 (PII) スキャン、ファイルタイプ検出をクライアントサイドで実行できます。

---

## Overview / 概要

| Item | Detail |
|------|--------|
| **Source Language** | Rust (edition 2024) |
| **Target Runtime** | Browser (wasm32-unknown-unknown) |
| **WASM Binding** | wasm-bindgen 0.2+ |
| **Build Tool** | wasm-pack |
| **Frontend** | Vanilla HTML / CSS / JS (ES6 Modules, no framework) |
| **UI Language** | Japanese (JA primary) |

### Features / 機能一覧

- **Drag & Drop ファイルアップロード** — ドラッグ＆ドロップまたはクリックでファイルを選択
- **ファイルタイプ自動検出** — マジックバイト解析により拡張子偽装を検知
- **PDF サニタイズ** — JavaScript / OpenAction / AcroForm の除去
- **Office サニタイズ** — VBA マクロプロジェクトの削除 (DOCX/XLSX/PPTX)
- **PII スキャン** — 日本政府対応 PII ルールセット（マイナンバー、メール、電話番号等）
- **3種のサニタイズポリシー** — StripActiveContent / ConvertToFlat / TextOnly
- **リアルタイム結果表示** — 脅威数、監査レポート(JSON)、サイズ比較、ダウンロード
- **ダークテーマ UI** — 政府・エンタープライズ向けプロフェッショナルデザイン

---

## Prerequisites / 前提条件

```bash
# Required tools
rustup target add wasm32-unknown-unknown   # WASM ターゲット追加
wasm-pack --version                         # >= 0.13.0

# Optional: for serving demo page
npx serve --version    # or any static HTTP server
```

### Browser Compatibility / 対応ブラウザ

| Browser | Minimum Version | Notes |
|---------|----------------|-------|
| Chrome  | 89+            | Full support (SharedArrayBuffer optional) |
| Firefox | 89+            | Full support |
| Safari  | 15.4+          | Full support |
| Edge    | 89+            | Full support (Chromium-based) |

> **Important**: The demo must be served over **HTTP or HTTPS**, not `file://` protocol.
> ES6 module imports (`import ... from "../pkg/..."`) require a proper origin.

## Cross-Origin Isolation (COOP/COEP) / クロスオリジン分離

The demo page includes COOP/COEP meta tags for SharedArrayBuffer and
Cross-Origin Isolation support — required for advanced WebAssembly features
(multi-threaded WASM, high-resolution timers):

```html
<meta http-equiv="Cross-Origin-Opener-Policy" content="same-origin">
<meta http-equiv="Cross-Origin-Embedder-Policy" require-corp="true">
```

### Local Development Headers / ローカル開発時のヘッダー設定

For local development, use an HTTP server that sets these headers:

```bash
# Option A: npx serve with CORS headers (recommended)
npx serve examples/wasm-browser --cors-headers

# Option B: Python built-in server (requires manual header configuration)
cd examples/wasm-browser && python -m http.server 8080
```

### Graceful Degradation / グレースフルデグラデーション

If COOP/COEP headers are not set, the demo degrades gracefully:
- [`detectCoopCoep()`](feature-detection.js) detects missing headers at runtime
- Falls back to single-threaded WASM execution
- Shows a non-blocking informational banner to the user
- All core sanitization functionality remains operational

See [`feature-detection.js`](feature-detection.js) and [`wasm-loader.js`](wasm-loader.js)
for implementation details.

---

## Quick Start / クイックスタート

### Step 1: Build WASM Package / WASM パッケージのビルド

Project root (`d:\Code\Misogi`) から以下を実行:

```bash
# Build the misogi-wasm crate to pkg/ directory (browser target only)
wasm-pack build crates/misogi-wasm --target web --release \
  --out-dir crates/misogi-wasm/pkg \
  -- --no-default-features --features browser
```

This produces:
```
crates/misogi-wasm/pkg/
├── misogi_wasm.js        # JS glue code (ES module)
├── misogi_wasm_bg.wasm   # Compiled WASM binary (**271.2 KB**, wasm-opt -Oz optimized)
├── misogi_wasm_d.ts      # TypeScript type definitions
└── package.json          # NPM package metadata
```

The `app.js` file imports from `../pkg/misogi_wasm.js`, which resolves to this output directory relative to `examples/wasm-browser/`.

### Step 2: Serve Demo Page / デモページの起動

```bash
# Option A: Using npx serve (recommended)
npx serve examples/wasm-browser

# Option B: Using Python built-in server
cd examples/wasm-browser
python -m http.server 8080

# Option C: Using any other static file server
# Just serve the examples/wasm-browser/ directory with HTTP
```

Open your browser to the served URL (typically `http://localhost:3000` or `http://localhost:8080`).

### Step 3: Use the Demo / デモの使用方法

1. **WASM ロード待機** — 初回アクセス時に WASM モジュールが読み込まれます（ローディングオーバーレイ表示）
2. **ファイルアップロード** — PDF または Office ファイルをドロップゾーンにドラッグ＆ドロップ
3. **ファイルタイプ確認** — 自動検出されたファイルタイプと信頼度が表示されます
4. **ポリシー選択** — サニタイズポリシーを選択（デフォルト: アクティブコンテンツ除去）
5. **サニタイズ実行** — 「サニタイズ実行」ボタンをクリック
6. **結果確認** — 脅威数、詳細レポート、PII スキャン結果を確認
7. **ダウンロード** — サニタイズ済みファイルをダウンロード

---

## Project Structure / プロジェクト構成

```
examples/wasm-browser/
├── index.html              # Main demo page (Japanese UI, dark theme, COOP/COEP meta tags)
├── style.css               # Professional stylesheet (CSS variables, responsive)
├── app.js                  # Application logic (ES6 module, feature-detection integration)
├── feature-detection.js    # Feature detection module (WASM/SAB/COOP-COEP, error localization)
├── wasm-loader.js          # WASM loader with timeout management and progressive loading
└── README.md               # This file

crates/misogi-wasm/                    # WASM crate source
├── src/
│   ├── lib.rs                         # Conditional module exports (dual-target: native + browser)
│   ├── wasm_compat.rs                 # Target-agnostic sanitizer implementations
│   ├── ffi.rs                         # [browser] wasm-bindgen FFI bindings
│   ├── js_glue.rs                     # [browser] JS interop helpers (localize_error, console_log)
│   ├── abi.rs / adapter.rs / ...       # [native] wasmi plugin runtime modules
│   └── benches/                       # Criterion performance benchmarks (8 groups, 26 tests)
├── Cargo.toml                           # Dual-feature configuration (native / browser)
├── pkg/                                 # Build output (generated by wasm-pack)
│   ├── misogi_wasm.js                  # ← Imported by app.js via ../pkg/misogi_wasm.js
│   ├── misogi_wasm_bg.wasm             # ← 271.2 KB optimized WASM binary
│   └── ...
└── tests/browser_compat/               # Playwright browser compatibility tests
    ├── playwright.config.ts            # 4-browser matrix config
    ├── helpers.ts                      # Test utilities (WASM wait, file upload, assertions)
    ├── wasm-load.spec.ts               # 8 test cases: loading + capability detection
    ├── sanitize-e2e.spec.ts            # 8 test cases: E2E sanitization flows
    └── generate-report.js              # Markdown compatibility matrix generator
```

---

## API Reference / API リファレンス

### Exported WASM Functions / エクスポート関数

| Function | Signature | Description |
|----------|-----------|-------------|
| `sanitize_pdf(data, policy?)` | `(Uint8Array, enum?) -> SanitizeResult` | PDF 文書のサニタイズ（JS/OpenAction/AcroForm 除去） |
| `sanitize_office(data, policy?)` | `(Uint8Array, enum?) -> SanitizeResult` | Office 文書のサニタイズ（VBA マクロ削除） |
| `scan_pii(data, pii_types?)` | `(Uint8Array, string[]?) -> PiiScanResult` | 個人情報スキャン（日本政府ルールセット） |
| `detect_file_type(magic_bytes)` | `(Uint8Array) -> FileTypeDetectionResult` | マジックバイトによるファイルタイプ検出 |
| `get_max_file_size()` | `() -> number` | 最大許容ファイルサイズ（バイト単位） |
| `compute_md5(data)` | `(Uint8Array) -> string` | MD5 ハッシュ計算 |
| `compute_sha256(data)` | `(Uint8Array) -> string` | SHA-256 ハッシュ計算 |

### Policy Enum Values / ポリシー列挙値

| Value | Japanese Label | Description |
|-------|---------------|-------------|
| `StripActiveContent` | アクティブコンテンツ除去 | JS/VBA/Macros を除去。書式維持（標準／デフォルト） |
| `ConvertToFlat` | フラット変換 | 全インタラクティブ要素破棄（最大セキュリティ） |
| `TextOnly` | テキストのみ抽出 | 書式・画像・レイアウト全て破棄（最小出力） |

### Return Types / 戻り値型

#### SanitizeResult
```typescript
{
  output_data: Uint8Array;     // サニタイズ済みファイルバイト
  threats_found: number;       // 除去された脅威の数
  report: string;              // JSON 形式の監査レポート
}
```

#### PiiScanResult
```typescript
{
  found: boolean;                          // PII が検出されたか
  matches: Array<{
    pii_type: string;                      // PII 種別 ("my_number", "email", ...)
    offset: number;                        // バイトオフセット
    context: string;                       // 周辺テキスト抜粋
  }>;
  recommended_action: string;             // "block" | "mask" | "alert_only"
}
```

#### FileTypeDetectionResult
```typescript
{
  detected_type: string;   // MIME type (e.g., "application/pdf")
  extension: string;       // 拡張子 (e.g., "pdf", "docx")
  confidence: number;      // 信頼度 0.0–1.0
  is_blocked: boolean;     // ブロック対象かどうか
  block_reason: string | null; // ブロック理由
}
```

---

## Screenshots Description / スクリーンショット説明

### Initial State / 初期状態
- Dark background with Misogi CDR shield logo header
- Large dashed-border drop zone in center with cloud upload icon
- Text: "ここにファイルをドロップしてください"
- WASM loading overlay visible until module initializes

### After File Drop / ファイルドロップ後
- Drop zone remains visible but file info card appears below it
- File info card shows: file icon, filename, size, detected type badge, confidence %
- If file is blocked (EXE etc.): red warning banner with block reason
- If file >50MB: amber warning about browser memory limits
- Policy selector radio buttons appear (3 options with descriptions)
- "Sanitize Execute" button + "Reset" button appear in action bar

### After Sanitization / サニタイズ完了後
- Results panel slides into view with card grid layout:
  - **Threat Status Card**: Large number (green if 0, red if >0), status indicator dot
  - **Size Comparison Card**: Original size vs sanitized size with delta percentage
  - **Report Card**: Expandable/collapsible JSON audit report (pretty-printed)
  - **PII Table** (if found): Matched PII types with offsets and context excerpts
  - **Download Card**: Green download button with sanitized filename and size
- Error banner appears only on failure (dismissible)

---

## Performance Expectations / パフォーマンス目安

| Operation | Expected Throughput | Notes |
|-----------|---------------------|-------|
| PDF Sanitization (analyze) | **~200 MiB/s** | Nom parser-based threat scanning (measured via criterion) |
| PDF Sanitization (full) | **~5 MB/s** | Analyze + remediate + rebuild (measured) |
| Office Sanitization | **~2 MB/s** | ZIP archive extraction + VBA removal (measured) |
| PII Scan | **~20 MB/s** | Regex-based text scanning (measured) |
| File Type Detection | <1ms | Magic byte lookup (first 262 bytes) |
| WASM Init | 100–500ms | One-time cost on page load |

### Binary Size / バイナリサイズ

| Metric | Value | Budget | Status |
|--------|-------|--------|--------|
| Raw `.wasm` | **271.2 KB** | < 8 MB | ✅ 3.4% of budget |
| Gzip compressed | **~75 KB** | < 3 MB | ✅ 2.5% of budget |
| Optimization | `wasm-opt -Oz` + `--remove-name-section --remove-dwarf` | — | — |

> Actual performance depends on device hardware, browser engine optimization,
> and input file complexity (e.g., heavily obfuscated PDFs may be slower).
> Benchmarks available: run `cargo bench -p misogi-wasm --bench wasm_perf` from workspace root.

### Memory Considerations / メモリに関する注意事項

- All processing runs in browser linear memory (WASM heap)
- Maximum file size: **500 MiB** (enforced by `MAX_WASM_FILE_SIZE_BYTES`)
- Files larger than **50 MB** trigger a user warning (browser memory pressure)
- Blob URLs are revoked after download to prevent memory leaks
- No data is transmitted to any external server

---

## Automated Compatibility Testing / 自動互換性テスト

The Playwright test suite in `tests/browser_compat/` provides automated
cross-browser validation of the WASM demo.

### Test Matrix / テストマトリックス

| Test Suite | Coverage | Test Cases |
|-----------|----------|------------|
| WASM Module Loading | FFI function availability, error-free init, loading indicator visibility | 8 |
| PDF Sanitization E2E | Clean PDF flow, malicious PDF rejection, error display | 2 |
| Office Sanitization E2E | DOCX VBA stripping, format preservation | 1 |
| PII Scan Display | Match rendering, Japanese context excerpts | 1 |
| Download Functionality | Blob URL generation, MIME type, filename correctness | 1 |
| Error Display | Japanese messages, user-friendly formatting, dismissibility | 1 |
| Large File Handling | ~10 MB files without OOM or crash | 1 |
| COOP/COEP Fallback | Graceful degradation when headers missing | 1 |

**Total**: 16 test cases × 4 browser projects (Chrome×2/Firefox/Safari) = **64 test points**

### Running Tests / テストの実行

```bash
cd crates/misogi-wasm/tests/browser_compat

# Install dependencies (first time)
npm install
npx playwright install chromium    # Minimum: Chromium only
npx playwright install             # Full: Chromium + Firefox + WebKit

# Run all tests (headless, CI mode)
npm test

# Run with visible browser window
npm run test:headed

# Interactive UI mode (select specific tests)
npm run test:ui

# Generate compatibility matrix report (Markdown)
node generate-report.js
# Output: COMPATIBILITY_MATRIX.md
```

### Reports / レポート

| Artifact | Location | Retention |
|----------|----------|-----------|
| HTML Report | `playwright-report/index.html` | Session |
| JSON Results | `results.json` | Session |
| Screenshots | `screenshots/` (on failure only) | 30 days |
| Compatibility Matrix | `COMPATIBILITY_MATRIX.md` | Manual |

---

## Troubleshooting / トラブルシューティング

### WASM loading fails / WASM の読み込みに失敗する

**Symptom**: Loading overlay shows error message about build required.

**Solution**: Ensure you have run the build command:
```bash
wasm-pack build crates/misogi-wasm --target web --release \
  --out-dir crates/misogi-wasm/pkg \
  -- --no-default-features --features browser
```

Verify that `crates/misogi-wasm/pkg/misogi_wasm.js` and `misogi_wasm_bg.wasm` exist.

### CORS errors when loading WASM / WASM 読み込み時に CORS エラー

**Symptom**: Console shows CORS-related errors for `.wasm` file.

**Solution**: You must use an HTTP server, not `file://` protocol:
```bash
npx serve examples/wasm-browser
# Do NOT open index.html directly as a file
```

### Blank page after loading / 読み込み後に白画面

**Symptom**: Page loads but nothing renders.

**Check**:
1. Open browser DevTools (F12) → Console tab for JS errors
2. Verify the `../pkg/` path resolves correctly relative to `app.js`
3. Check that `wasm-pack` was built with `--target web` (not `--target bundler`)

---

## Security Notes / セキュリティに関する注意

- All file processing occurs entirely within the browser sandbox
- No network requests are made during sanitization (zero server dependency)
- WASM memory is isolated per-tab and cleared on page navigation
- Output blobs are created with correct MIME types to prevent MIME sniffing attacks
- User-facing error messages do not expose internal stack traces or file paths
- Content Security Policy headers are recommended for production deployment

---

## Related Links / 関連リンク

- [Misogi WASM Crate](../../crates/misogi-wasm/) — Rust WASM バインディングソース
- [Misogi CDR Engine](../../crates/misogi-cdr/) — CDR コアエンジン
- [Misogi Core](../../crates/misogi-core/) — 共通ライブラリ
- [Parent Examples Index](../README.md) — 全サンプル一覧
- [wasm-pack Documentation](https://rustwasm.github.io/docs/wasm-pack/) — 公式ドキュメント
