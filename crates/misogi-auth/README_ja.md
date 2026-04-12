# misogi-auth

Misogi 向け認証・認可フレームワーク

## 概要

`misogi-auth` は、Misogi ファイル転送システムのための包括的な認証・認可フレームワークを提供します。日本の組織階層と LGWAN（地方公共団体広域ネットワーク）コンプライアンス要件に準拠したロールベースアクセス制御（RBAC）を実装しています。

## 機能

### コア機能

- **ロールベースアクセス制御（RBAC）**: 階層的な権限モデル
- **セッション管理**: ライトウェイトなトークンベース認証
- **ユーザーストア**: プラグ可能なバックエンドを持つファイルベース JSON ストレージ
- **日本組織アライメント**: 公共部門ワークフロー向けに設計
- **外部 IDP 対応**: LDAP/Active Directory/SAML 統合向けに構造化

### ユーザーロール

システムは日本の組織構造に準拠した 3 つの異なるロールを実装しています：

#### Staff（一般職員）
- **権限**: ファイルアップロードと転送リクエスト作成
- **制限**: 転送リクエストの承認は不可
- **用途**: ファイル転送を開始する一般従業員

#### Approver（上長承認者）
- **権限**: ファイルアップロード、転送の承認/拒否
- **権限**: スタッフメンバーからのリクエストを承認可能
- **用途**: 部門管理者、課長
- **コンプライアンス**: LGWAN 準拠ワークフローに必須

#### Admin（管理者）
- **権限**: 完全なシステムアクセス
- **機能**: ユーザー管理、監査ログエクスポート、設定変更
- **用途**: システム管理者、IT スタッフ

## アーキテクチャ

```
┌─────────────────┐
│  クライアントリクエスト │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  認証           │
│  ミドルウェア    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  セッショントークン│
│  検証           │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ロールベース    │
│  認可           │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  リソースアクセス│
│  （許可/拒否）   │
└─────────────────┘
```

## インストール

`Cargo.toml` に追加：

```toml
[dependencies]
misogi-auth = { path = "../misogi-auth" }
```

## 使用方法

### ユーザーの作成

```rust
use misogi_auth::{User, UserRole};

// スタッフメンバーの作成
let staff = User::staff("EMP001", "田中 太郎");

// 承認者の作成
let approver = User::approver("MGR001", "佐藤 次長");

// 管理者の作成
let admin = User::admin("ADMIN001", "鈴木 管理者");

// 特定のロールを持つカスタムユーザー
let user = User::new(
    "EMP002".to_string(),
    "山田 花子".to_string(),
    UserRole::Staff,
);
```

### セッション管理

```rust
use misogi_auth::{User, SessionToken};

// ユーザーの作成
let user = User::staff("EMP001", "田中 太郎");

// セッショントークンの生成（8 時間 TTL）
let token = SessionToken::new(&user, 8);

// 有効期限の確認
if token.is_expired() {
    println!("セッションが期限切れです。再認証してください");
} else {
    println!("トークンの有効期限：{}", token.expires_at);
}
```

### ロールベースの認可

```rust
use misogi_auth::{User, UserRole};

let staff = User::staff("EMP001", "田中 太郎");
let approver = User::approver("MGR001", "佐藤 次長");
let admin = User::admin("ADMIN001", "鈴木 管理者");

// アップロード権限の確認
assert!(staff.role.can_upload());      // true
assert!(approver.role.can_upload());   // true
assert!(admin.role.can_upload());      // true

// 承認権限の確認
assert!(!staff.role.can_approve());    // false
assert!(approver.role.can_approve());  // true
assert!(admin.role.can_approve());     // true

// 管理権限の確認
assert!(!staff.role.can_administer());    // false
assert!(!approver.role.can_administer()); // false
assert!(admin.role.can_administer());     // true
```

### ユーザーストア操作

```rust
use misogi_auth::{User, UserStore, UserRole};
use std::path::Path;

// ユーザーストアの初期化
let store = UserStore::new(Path::new("users.json")).await?;

// ユーザーの追加
let user = User::staff("EMP001", "田中 太郎");
store.add_user(&user).await?;

// ユーザーの取得
let retrieved = store.get_user("EMP001").await?;
assert_eq!(retrieved.display_name, "田中 太郎");

// ユーザーロールの更新
store.update_user_role("EMP001", UserRole::Approver).await?;

// 全ユーザーの一覧
let users = store.list_users().await?;
for user in users {
    println!("{} - {} ({})", 
        user.user_id, 
        user.display_name, 
        user.role.display_name_jp()
    );
}
```

## API リファレンス

### User 構造体

コアユーザー表現：

```rust
pub struct User {
    pub user_id: String,           // 一意の識別子
    pub display_name: String,      // 日本語形式の名前
    pub email: Option<String>,     // オプションのメールアドレス
    pub department: Option<String>, // 組織単位
    pub role: UserRole,            // 割り当てられたロール
    pub created_at: DateTime<Utc>, // 作成タイムスタンプ
    pub is_active: bool,           // アカウントステータス
}
```

### SessionToken 構造体

ライトウェイトな認証トークン：

```rust
pub struct SessionToken {
    pub token_id: String,          // 一意のトークン識別子
    pub user_id: String,           // 関連するユーザー ID
    pub user_name: String,         // キャッシュされたユーザー名
    pub role: UserRole,            // キャッシュされたロール
    pub created_at: DateTime<Utc>, // 作成時間
    pub expires_at: DateTime<Utc>, // 有効期限
}
```

### UserRole 列挙型

権限メソッドを持つロール分類：

```rust
pub enum UserRole {
    Staff,    // 一般職員
    Approver, // 上長承認者
    Admin,    // 管理者
}

impl UserRole {
    pub fn can_upload(&self) -> bool;
    pub fn can_approve(&self) -> bool;
    pub fn can_administer(&self) -> bool;
    pub fn display_name_jp(&self) -> &'static str;
}
```

### UserStore

永続的ユーザー保存：

```rust
pub struct UserStore {
    // 内部ストレージバックエンド
}

impl UserStore {
    pub async fn new(path: &Path) -> Result<Self>;
    pub async fn add_user(&self, user: &User) -> Result<()>;
    pub async fn get_user(&self, user_id: &str) -> Result<User>;
    pub async fn update_user(&self, user: &User) -> Result<()>;
    pub async fn update_user_role(&self, user_id: &str, role: UserRole) -> Result<()>;
    pub async fn delete_user(&self, user_id: &str) -> Result<()>;
    pub async fn list_users(&self) -> Result<Vec<User>>;
}
```

## セキュリティに関する考慮事項

### トークンセキュリティ

現在の実装ではライトウェイトなセッショントークンを使用：
- **ストレージ**: インメモリまたはファイルベース JSON
- **有効期限**: 設定可能な TTL（Time To Live）
- **検証**: すべてのリクエストで有効期限チェック

**本番推奨**: エンタープライズ ID プロバイダーからの JWT/OIDC トークンに置き換えてください。

### パスワード処理

現在の実装にはパスワード管理が含まれていません：
- 外部 IDP 統合向けに設計
- 開発/テスト用のみローカルストレージ
- 本番展開では以下を使用すべき：
  - LDAP/Active Directory
  - SAML 2.0 ID プロバイダー
  - OAuth2/OpenID Connect

### アクセス制御

ロールベースの権限は API レイヤーで強制されます：
- すべてのエンドポイントはセッショントークンを検証
- リソースアクセス前にロールチェックを実行
- すべての認可決定の監査ロギング

### 監査証跡

すべての認証・認可イベントがログに記録されます：
- ログイン試行（成功/失敗）
- トークン生成と検証
- ロールベースアクセス決定
- 管理アクション

## 統合パターン

### エンタープライズ IDP 統合

```rust
// 例：LDAP 統合パターン
async fn authenticate_with_ldap(username: &str, password: &str) -> Result<User> {
    // LDAP ディレクトリのクエリ
    let ldap_entry = ldap_client.search(username).await?;
    
    // 認証情報の検証
    ldap_client.bind(username, password).await?;
    
    // LDAP 属性を Misogi ユーザーにマッピング
    let user = User {
        user_id: ldap_entry.uid,
        display_name: ldap_entry.cn,
        email: Some(ldap_entry.mail),
        department: ldap_entry.ou,
        role: map_ldap_group_to_role(&ldap_entry.groups),
        created_at: Utc::now(),
        is_active: true,
    };
    
    Ok(user)
}
```

### ミドルウェア統合

```rust
// 例：認証のための Axum ミドルウェア
async fn auth_middleware(
    req: Request<Body>,
    next: Next<Body>,
) -> Result<Response> {
    // ヘッダーからトークンを抽出
    let token = extract_token(&req)?;
    
    // トークンを検証
    let user = store.validate_token(&token).await?;
    
    // ユーザーをリクエスト拡張に追加
    req.extensions_mut().insert(user);
    
    // ハンドラーに続行
    Ok(next.run(req).await)
}
```

## エラーハンドリング

包括的なエラータイプ：

```rust
pub enum AuthError {
    #[error("ユーザーが見つかりません：{0}")]
    UserNotFound(String),
    
    #[error("認証情報が無効です")]
    InvalidCredentials,
    
    #[error("セッションが期限切れです")]
    SessionExpired,
    
    #[error("権限が不足しています：必要 {required}、所持 {has}")]
    InsufficientPermissions {
        required: UserRole,
        has: UserRole,
    },
    
    #[error("ユーザーアカウントが無効です：{0}")]
    AccountInactive(String),
    
    #[error("I/O エラー：{0}")]
    Io(#[from] std::io::Error),
    
    #[error("JSON エラー：{0}")]
    Json(#[from] serde_json::Error),
}
```

## テスト

テストスイートの実行：

```bash
cargo test -p misogi-auth
```

### テストカバレッジ

- ユーザー作成と管理
- セッショントークンのライフサイクル
- ロールベースの認可
- ユーザーストア操作
- エラーハンドリングシナリオ

## 依存関係

- `tokio`: 非同期ランタイム
- `serde`: シリアライゼーションフレームワーク
- `serde_json`: JSON 処理
- `uuid`: 一意の識別子
- `chrono`: 日付と時刻の処理
- `thiserror`: エラーハンドリング
- `tracing`: ロギングと診断

## パフォーマンス

### ベンチマーク

典型的な操作レイテンシ：

| 操作 | レイテンシ |
|------|-----------|
| トークン検証 | < 1 ms |
| ユーザー検索 | < 5 ms |
| ロールチェック | < 0.1 ms |
| トークン生成 | < 2 ms |

### 最適化のヒント

1. **トークンキャッシング**: 繰り返しリクエストのために検証済みトークンをキャッシュ
2. **コネクションプーリング**: 外部 IDP のためにコネクションプールを使用
3. **非同期 I/O**: 非ブロッキング操作のために Tokio を活用
4. **バッチ操作**: 可能な場合、ユーザーストア操作をバッチ処理

## 本番展開

### 推奨アーキテクチャ

```
┌─────────────────┐
│  アプリケーション  │
│  （Misogi）      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  認証ミドルウェア  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  エンタープライズ │
│  IDP            │
│  （LDAP/AD/SAML）│
└─────────────────┘
```

### 設定

```toml
# config.toml の例
[auth]
# セッショントークン TTL（時間）
session_ttl_hours = 8

# 外部 IDP 設定
[idp]
type = "ldap"
server = "ldap://ad.example.com"
base_dn = "dc=example,dc=com"
bind_dn = "cn=misogi,ou=services,dc=example,dc=com"
# 認証情報には環境変数を使用
```

### セキュリティ強化

1. **外部 IDP の使用**: 認証情報をアプリケーションに保存しない
2. **TLS の有効化**: すべての認証トラフィックを暗号化
3. **短い TTL**: 短いセッショタイムアウト（4-8 時間）を使用
4. **監査ロギング**: すべての認証イベントを SIEM にログ
5. **レート制限**: 総当たり攻撃を防止
6. **MFA サポート**: 多要素認証を統合

## コントリビュート

コントリビューションを歓迎します！以下の点にご注意ください：
- すべてのコードは Rust 2024 Edition でコンパイル可能であること
- 包括的なドキュメントが必要
- セキュリティ関連の変更にはテストが必須
- 認証ロジックの変更にはセキュリティレビューが必要

## ライセンス

Apache 2.0 ライセンスの下でライセンスされています。詳細は [LICENSE](../../LICENSE) を参照してください。

---

**セキュリティ通知**: このモジュールは認証フレームワークを提供します。セキュリティコンプライアンスのため、本番展開では必ずエンタープライズ ID プロバイダーと統合してください。
