# 変更ログ

Misogi のすべての注目すべき変更はこのファイルに記録されます。

このフォーマットは [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) に基づいており、
このプロジェクトは [Semantic Versioning](https://semver.org/spec/v2.0.0.html) に準拠しています。

## [未リリース]

### 予定されている機能
- ウェブベースのモニタリングダッシュボード
- 拡張されたロギングおよび観測性機能
- 並列チャンキングによるファイル転送パフォーマンスの向上

### 変更 (v0.2.0 開発中)

#### 修正
- **`misogi-wasm` クレートの全26コンパイルエラーを解決** — WASM FFI レイヤーがクリーンにコンパイル可能に
- `misogi-wasm` の依存関係修正: `misogi-core`, `zip`, `tokio` を直接依存に追加; `wasm-bindgen` の `serde-serialize` フィーチャを有効化
- WASMエクスポート構造体の `String`/`Vec<u8>` フィールドにおける Copy trait bound 問題を `#[wasm_bindgen(getter_with_clone)]` で修正
- `misogi_core::pii` 経由の `PIIAction`, `PIIDetector` trait の private 可視性問題を修正
- `RegexPIIDetector` イテレータ曖昧性を UFCS 構文 (`PIIDetector::scan()`) で修正
- Office サニタイザー WASM アダプタの `FileOptions` 型注釈を修正
- `misogi-core` の警告約22件をクリーンアップ（未使用インポート、未使用変数、デッドコード）

#### misogi-cdr — PDF True CDR エンジン強化
- **線形化PDF検出**: `/Linearized` PDF を検出し、クロスリファレンスストリームを従来の xref テーブルに平坦化
- **インライン画像検証**: BI/ID/EI シーケンススキャン; FlateDecode/LZWDecode インライン画像をブロック（ステガノグラフィーベクタ）; ASCIIHex/ASCII85/DCT/CCITTFax のみ許可
- **難読化オペレータ名検出`: Hexエンコード `#HH` オペレータデコード; 難読化された危険コマンド (`#4A#53` = JS) を検出
- **カラースペース検証**: DeviceRGB/CMYK/Gray/CalRGB/CalGRAY を許可リスト化; ICCBased/Lab/Separation/DeviceN などの疑わしいスペースをブロック
- **MediaBox 継承検証**: MediaBox 解決のためのページツリー再帰走査; デフォルトはレターサイズ [0 0 612 792]
- **複数コンテンツストリーム処理**: `/Contents` 配列の適切な連結とストリームごとの SAFE_OPERATORS フィルタリング

#### misogi-cdr — Office CDR 深化
- **XML Endイベント名追跡**: 名前スタックメカニズムによるバランスタグ出力を修正（以前は TODO/スタブ）
- **DDE攻撃防止**: セル値/数式の `=CMD|`, `=EXEC(`, `=MSQUERY` パターンスキャン; 外部リンクプロトコルブロック (`file://`, `javascript:`, `vbscript:`)
- **Excel固有脅威**: sheetProtection パスワード削除, PivotCache 外部参照検出, カスタムXMLマッピング注入スキャン, データ検証URLフィルタリング
- **Word固有脅威**: altChunk 削除（外部コンテンツ埋め込み）, 危険なハイパーリンクプロトコルブロック, IRM権限削除, instrText スクリプト注入無効化
- **PowerPoint固有脅威**: OLE オブジェクト偽装画像検出, 外部サウンド参照検証, extLst（ゼロデイベクタ）削除, アニメーションコマンドスクリプト注入フィルタリング
- **16種類の新規 OoxmlCdrAction バリアント**による詳細監査トレール

#### misogi-auth — OIDC 本番強化
- **JWKS 鍵ローテーション**: 不明な `kid` 発生時の自動リフレッシュ; 設定可能な TTL（デフォルト3600秒）; G-Cloud 向けに7200秒に拡張
- **トークンリフレッシュフロー**: `refresh_access_token()` (grant_type=refresh_token 対応)
- **RP開始ログアウト`: `initiate_logout()` (id_token_hint + post_logout_redirect_uri)
- **Nonce バインド検証**: Nonce ストア（TTL デフォルト300秒）; 有効期限切れエントリの自動クリーンアップ
- **IdP固有アダプタ**: Keycloak, Azure AD, Okta, 日本 G-Cloud 用プリ設定ファクトリ関数
- **ミドルウェア統合**: `OidcExtractor` (Axum FromRequestParts), `OidcGrpcInterceptor` (tonic gRPC), セキュアセッションCookie設定

#### misogi-auth — SAML 2.0 完全実装
- **コアプロトコル**: AuthnRequest 生成 (deflate+base64), Response 解析 (base64+inflate+XML), ring による XML署名検証, Conditions 検証 (NotBefore/NotOnOrAfter/Audience/Destination), リプレイ攻撃 LRU キャッシュ
- **日本 IdP 互換性**: G-Cloud 属性マッピング (urn:oid:... パターン), 都道府県柔軟マッピング, NameID Format 処理 (persistent/transient/email)
- **メタデータ交換**: SP メタデータ XML 生成, IdP メタデータ解析（自動リフレッシュ対応）
- **ルートハンドラーテンプレート**: /saml/login, /saml/acs, /saml/logout, /saml/metadata エンドポイント

#### misogi-auth — 認証エンジン統合
- **マルチバックエンド認証ストラテジ**: Sequential / FirstMatch / Required モード; 設定可能なバックエンド順序 (JWT → OIDC → LDAP → SAML → API Key)
- **統合ユーザーアイデンティティ解決**: クロスバックエンドユーザーマッピングから `UnifiedUser` 構造体へ（ロール、グループ、属性含む）
- **外部 IdP からのロールマッピング`: 正規表現ベースルール（優先度付き）; 組み込み企業マッピング (Admin/Approver/Staff); 日本語グループ名対応
- **監査ログ統合**: リングバッファ (10Kイベント); SIEM対応 JSON エクスポート; イベントごとのタイムスタンプ/バックエンド/IP/詳細
- **トークン交換サービス**: 外部 IdP 認証 → Misogi 内部 JWT (RS256 署名); 下流サービスは Misogi 公開鍵のみで検証

## [0.1.0] - 2026-04-11

### 追加

#### コア機能
- **初期リリース** の Misogi ファイル転送システム
- 設定可能なチャンクサイズを備えた**チャンクファイル転送**
- 詳細な進捗追跡によるファイル転送の**リアルタイムモニタリング**
- 信頼性の高いストリーミングのための**gRPC ベースの通信**
- **デュアルモード操作**（サーバーモードとデーモンモード）
- Rust 2024 Edition を使用した**型安全な実装**

#### misogi-core
- gRPC サービスのための Protocol Buffer 定義
- ファイル整合性検証のためのハッシュユーティリティ（MD5）
- `thiserror` を使用した包括的なエラーハンドリング
- コア型定義とデータ構造
- Tokio を使用した async/await サポート

#### misogi-sender
- HTTP API によるファイルアップロード（Axum ベース）
- 受信者通信のための gRPC ストリーミングクライアント
- `notify` によるファイルシステムモニタリング
- 効率的な転送のための設定可能なチャンクサイズ
- 進捗追跡とステータス報告
- `clap` を使用した CLI インターフェース
- TOML ベースの設定

#### misogi-receiver
- チャンクファイルストリーム受信のための gRPC サーバー（Tonic ベース）
- ファイル取得のための HTTP ダウンロードエンドポイント
- 受信したチャンクからのファイル再構築
- メタデータ付きの整理されたファイル保存
- 直接送信者 - 受信者通信のためのトンネルモードサポート
- リアルタイム受信ステータスモニタリング
- `clap` を使用した CLI インターフェース
- TOML ベースの設定

#### misogi-cdr
- Content Disarm and Reconstruction（CDR）エンジン
- PPAP（Penetration Test as a Service）検出と処理
- 複数のファイルタイプのサポート：
  - PDF 文書
  - Microsoft Office ファイル（Word、Excel、PowerPoint）
  - 画像ファイル
- 設定可能な sanitization ポリシー
- セキュリティ重視のファイル変換

#### misogi-auth
- 認証および認可フレームワーク
- ロールベースアクセス制御（RBAC）
- JWT トークンサポート
- 安全な認証情報保存
- 権限管理システム

#### ドキュメント
- バイリンガル README（英語と日本語）
- コードスタイルガイドラインを含む CONTRIBUTING ガイド
- 脆弱性報告プロセスを含む SECURITY ポリシー
- GitHub イシューテンプレート（バグ報告と機能リクエスト）
- プルリクエストテンプレート
- クレート固有の README ファイル

#### 開発ツール
- 包括的なテストスイート
- `rustfmt` によるコードフォーマット
- `clippy` によるリンティング
- `cargo doc` による API ドキュメント生成

### セキュリティ

- gRPC 接続のための TLS サポート
- MD5 ハッシングによるファイル整合性検証
- すべてのエンドポイントでの入力検証
- 安全なストレージ権限
- 監査証跡のための構造化 JSON ロギング
- ハードコードされた認証情報や秘密鍵なし

### 技術的詳細

#### 依存関係
- `tokio` - 非同期ランタイム
- `axum` - ウェブフレームワーク
- `tonic` - gRPC フレームワーク
- `prost` - Protocol Buffers 実装
- `serde` - シリアライゼーションフレームワーク
- `thiserror` - エラーハンドリング
- `clap` - CLI パーシング
- `notify` - ファイルシステムモニタリング
- `uuid` - 一意の識別子
- `chrono` - 日付と時刻の処理

#### アーキテクチャ
- 送信者 - 受信者アーキテクチャ
- チャンクファイル転送プロトコル
- 大規模ファイルのためのストリーミングサポート
- モジュール型クレート構造
- 将来の拡張のためのプラグ可能設計

### 既知の問題

- 初期リリース - 現時点で既知の問題なし

### 非推奨

- 初期リリースで非推奨のものなし

### 削除

- 初期リリースで削除されたものなし

---

## バージョン履歴

| バージョン | リリース日   | 説明         |
|-----------|-------------|-------------|
| 0.1.0     | 2026-04-11  | 初期リリース  |

---

## ライセンス

このプロジェクトは Apache 2.0 ライセンスの下でライセンスされています。
詳細は [LICENSE](LICENSE) を参照してください。

---

**注**: 各リリースの詳細については、GitHub リリースページを参照してください。
