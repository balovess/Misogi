# Active Directory / LDAP 連携ガイド

Misogi は Active Directory (AD) および LDAP サーバーとの連携をサポートし、
組織の既存認証基盤を活用したユーザー認証・認可を実現します。

**対象読者**: AD 管理者、SIer 設計担当者  
**前提条件**: Active Directory ドメイン環境が構築されていること

---

## 1. 概要

### 1-1. 連携アーキテクチャ

```
┌──────────────┐     LDAP/LDAPS (port 389/636)     ┌──────────────────┐
│   Misogi     │ ──────────────────────────────▶  │  Active Directory │
│  (Sender/    │ ◀── ユーザー情報 / グループ所属    │  Domain Controller│
│   Receiver)  │                                   │                  │
└──────────────┘                                   └──────────────────┘
       │
       ├── ユーザー認証 (Bind)
       ├── グループベース認可
       ├── 所属組織単位 (OU) の取得
       └── 属性検索 (mail, displayName 等)
```

### 1-2. サポートする機能

| 機能 | 説明 |
|------|------|
| ユーザー認証 | AD ユーザー名とパスワードによる Bind 認証 |
| グループ認可 | AD グループ所属に基づくアクセス制御 |
| OU ベース検索 | 組織単位 (Organizational Unit) からのユーザー検索 |
| TLS/LDAPS | 暗号化通信 (port 636) |
| StartTLS | 平文接続からの TLS アップグレード |

---

## 2. 設定方法

### 2-1. `[ldap]` セクション

Sender および Receiver の設定ファイルに `[ldap]` セクションを追加します。

```toml
[ldap]
enabled = true
url = "ldaps://ad.example.com:636"
base_dn = "DC=example,DC=com"
bind_dn = "CN=MisogiService,OU=Service Accounts,DC=example,DC=com"
bind_password = "${LDAP_BIND_PASSWORD}"
user_search_base = "OU=Users,OU=Tokyo,DC=example,DC=com"
user_search_filter = "(sAMAccountName={username})"
group_search_base = "OU=Groups,DC=example,DC=com"
tls_verify_cert = true
ca_cert_path = "C:\\certs\\ad-ca.crt"
connection_timeout = 30
pool_size = 5
```

### 2-2. フィールド完全リファレンス

| フィールド | 型 | デフォルト | 必須 | 説明 |
|----------|-----|---------|------|------|
| `enabled` | Boolean | `false` | ✅ | LDAP/AD 連携の有効/無効 |
| `url` | String | — | ✅ | LDAP サーバー URL (`ldap://` または `ldaps://`) |
| `base_dn` | String | — | ✅ | ベース Distinguished Name |
| `bind_dn` | String | — | ✅ | システム Bind 用 DN（サービスアカウント） |
| `bind_password` | String | — | ✅ | Bind パスワード（環境変数参照推奨） |
| `user_search_base` | String | `base_dn` と同じ | △ | ユーザー検索のベース DN |
| `user_search_filter` | String | `"(sAMAccountName={username})"` | △ | ユーザー検索フィルタ |
| `group_search_base` | String | `base_dn` と同じ | △ | グループ検索のベース DN |
| `tls_verify_cert` | Boolean | `true` | △ | TLS 証明書の検証有無 |
| `ca_cert_path` | String | `""` | △ | CA 証明書ファイルパス（自己署名 CA 等） |
| `connection_timeout` | Integer | `30` | △ | 接続タイムアウト（秒） |
| `pool_size` | Integer | `5` | △ | LDAP コネクションプールサイズ |

---

## 3. Base DN の理解と設定例

### 3-1. Base DN とは

Base DN (Distinguished Name) は、LDAP 検索を開始する起点となるパスです。
Active Directory の階層構造に対応します。

### 3-2. 日本の組織における典型的な OU 構成例

#### 例 A: 地方自治体（都道府県庁）

```
DC=tokyo,DC=local
├── OU=本庁舎
│   ├── OU=総務部
│   │   ├── OU=企画課
│   │   │   └── CN=鈴木 一郎 (ユーザー)
│   │   └── OU=システム課
│   └── OU=環境生活部
├── OU=支庁
│   └── OU=多摩支庁
├── OU=サービスアカウント
│   └── CN=MisogiService (サービスアカウント)
└── OU=グループ
    ├── CN=Misogi_Operators (セキュリティグループ)
    └── CN=Misogi_Approvers (承認者グループ)
```

**この場合の設定例**:

```toml
[ldap]
enabled = true
url = "ldaps://dc01.tokyo.local:636"
base_dn = "DC=tokyo,DC=local"
bind_dn = "CN=MisogiService,OU=サービスアカウント,DC=tokyo,DC=local"
bind_password = "${MISOGI_LDAP_PW}"
user_search_base = "OU=本庁舎,DC=tokyo,DC=local"
group_search_base = "OU=グループ,DC=tokyo,DC=local"
```

#### 例 B: 省庁（中央省庁）

```
DC=gov,DC=jp
├── OU=Ministries
│   ├── OU=Somusho (総務省)
│   │   ├── OU=Users
│   │   └── OU=Groups
│   ├── OU=Rikamin (経済産業省)
│   └── OU=koumuhousho (厚生労働省)
└── OU=ServiceAccounts
```

**この場合の設定例**:

```toml
[ldap]
enabled = true
url = "ldaps://ldap.gov.jp:636"
base_dn = "DC=gov,DC=jp"
bind_dn = "CN=MisogiSvc,OU=ServiceAccounts,DC=gov,DC=jp"
user_search_base = "OU=Somusho,OU=Ministries,DC=gov,DC=jp"
group_search_base = "OU=Groups,OU=Somusho,OU=Ministries,DC=gov,DC=jp"
```

#### 例 C: 民間企業（SIer 標準）

```
DC=company,DC=co,DC=jp
├── OU=Tokyo
│   ├── OU=Employees
│   └── OU=IT_Department
├── OU=Osaka
│   └── OU=Employees
└── OU=Service_Accounts
```

**この場合の設定例**:

```toml
[ldap]
enabled = true
url = "ldap://dc.company.co.jp:389"
base_dn = "DC=company,DC=co,DC=jp"
bind_dn = "CN=MisogiSvc,OU=Service_Accounts,DC=company,DC=co,DC=jp"
user_search_base = "OU=Employees,OU=Tokyo,DC=company,DC=co,DC=jp"
tls_verify_cert = false  # 内部 LDAP の場合、StartTLS を使用
```

### 3-3. Base DN の確認方法

Active Directory Users and Computers (ADUC) または以下のコマンドで確認できます：

```powershell
# ドメインの Base DN を確認
(Get-ADDomain).DistinguishedName
# 出力例: DC=example,DC=com

# 特定ユーザーの DN を確認
Get-ADUser -Filter {sAMAccountName -eq "suzuki"} |
    Select-Object DistinguishedName
# 出力例: CN=鈴木 一郎,OU=企画課,OU=総務部,OU=本庁舎,DC=tokyo,DC=local
```

---

## 4. LDAP 検索フィルター

### 4-1. ユーザー検索フィルタ

`user_search_filter` で `{username}` はプレースホルダーとして、
実際のユーザー入力値に置き換えられます。

| フィルタパターン | 検索対象 | 使用例 |
|---------------|---------|--------|
| `(sAMAccountName={username})` | ユーザー名（デフォルト） | `suzuki` → `suzuki` で検索 |
| `(userPrincipalName={username})` | UPN 形式 | `suzuki@tokyo.local` |
| `(mail={username})` | メールアドレス | `suzuki@tokyo.lg.jp` |
| `(&(objectClass=user)(sAMAccountName={username}))` | objectClass 制限付き | より厳密な検索 |

### 4-2. グループ検索

Misogi はユーザーのグループ所属を確認し、アクセス制御に使用できます。

```toml
# グループ検索の設定
[group_mapping]
admin_group = "CN=Misogi_Admins,OU=Groups,DC=example,DC=com"
operator_group = "CN=Misogi_Operators,OU=Groups,DC=example,DC=com"
approver_group = "CN=Misogi_Approvers,OU=Groups,DC=example,DC=com"
```

---

## 5. TLS / LDAPS 設定

### 5-1. 接続方式の選択

| 方式 | URL 形式 | ポート | セキュリティ | 推奨環境 |
|------|---------|--------|------------|---------|
| 平文 LDAP | `ldap://` | 389 | ❌ 暗号化なし | テスト環境のみ |
| LDAPS | `ldaps://` | 636 | ✅ TLS 1.2+ | 本番推奨 |
| StartTLS | `ldap://` + StartTLS | 389→TLS | ✅ TLS 1.2+ | 本番可 |

### 5-2. LDAPS 設定例（本番推奨）

```toml
[ldap]
enabled = true
url = "ldaps://dc01.tokyo.local:636"
base_dn = "DC=tokyo,DC=local"
bind_dn = "CN=MisogiService,OU=ServiceAccounts,DC=tokyo,DC=local"
bind_password = "${MISOGI_LDAP_PW}"
tls_verify_cert = true
ca_cert_path = "C:\\ProgramData\\Misogi\\certs\\ad-root-ca.crt"
```

### 5-3. 自己署名 CA 証明書の取り込み

社内 CA が自己署名証明書を使用している場合：

```powershell
# AD ルート CA 証明書をエクスポート
# 1. DC 上で「証明書」MMC スナップインを開く
# 2. 「信頼されたルート証明機関」→ 該当 CA 証明書を右クリック
# 3. 「エクスポート」→ DER encoded X.509 (.cer) で保存

# Misogi サーバーに配置
New-Item -ItemType Directory -Path "C:\ProgramData\Misogi\certs" -Force
Copy-Item "ad-root-ca.cer" "C:\ProgramData\Misogi\certs\ad-root-ca.crt"
```

### 5-4. StartTLS 設定例

```toml
[ldap]
enabled = true
url = "ldap://dc01.tokyo.local:389"
base_dn = "DC=tokyo,DC=local"
# StartTLS は url が ldap:// であっても暗号化されます
use_start_tls = true
tls_verify_cert = true
```

---

## 6. サービスアカウントの作成

### 6-1. AD でのサービスアカウント作成手順

```powershell
# PowerShell でサービスアカウント作成
$Password = ConvertTo-SecureString "Complex_P@ssw0rd!_For_Misogi" `
    -AsPlainText -Force

New-ADUser -Name "MisogiService" `
    -SamAccountName "MisogiService" `
    -UserPrincipalName "MisogiService@tokyo.local" `
    -Path "OU=ServiceAccounts,DC=tokyo,DC=local" `
    -AccountPassword $Password `
    -Enabled $true `
    -PasswordNeverExpires $true `
    -Description "Service account for Misogi CDR system"

# パスワードを変更不可に設定（セキュリティ強化）
Set-ADUser -Identity "MisogiService" -CannotChangePassword $true
```

### 6-2. 最小権限の原則

サービスアカウントには以下の最小限の権限のみを付与してください：

| 必要な権限 | 目的 |
|-----------|------|
| ディレクトリ読み取り (Read) | ユーザー/グループ情報の検索 |
| Bind 権限 | 自身の認証 |

**不要な権限**:
- ❌ Domain Admins グループへの所属不要
- ❌ Enterprise Admins グループへの所属不要
- ❌ 他の OU への書き込み権限不要
- ❌ パスワードリセット権限不要

---

## 7. よくある構成パターン

### パターン 1: 単一ドメイン（小規模）

```toml
[ldap]
enabled = true
url = "ldaps://dc01:636"
base_dn = "DC=company,DC=local"
bind_dn = "CN=MisogiSvc,OU=ServiceAccounts,DC=company,DC=local"
bind_password = "${MISOGI_LDAP_PW}"
```

### パターン 2: 多拠点（OU 分離）

```toml
[ldap]
enabled = true
url = "ldaps://dc01:636"
base_dn = "DC=company,DC=co,DC=jp"
bind_dn = "CN=MisogiSvc,OU=ServiceAccounts,DC=company,DC=co,DC=jp"
bind_password = "${MISOGI_LDAP_PW}"
user_search_base = "OU=ActiveUsers,DC=company,DC=co,DC=jp"
```

### パターン 3: フォレスト間（複数ドメイン）

```toml
[ldap]
enabled = true
url = "ldaps://gc.company.co.jp:3268"
base_dn = "DC=company,DC=co,DC=jp"
bind_dn = "CN=MisogiSvc,OU=ServiceAccounts,DC=root,DC=company,DC=co,DC=jp"
bind_password = "${MISOGI_LDAP_PW}"
# Global Catalog (ポート 3268/3269) を使用してフォレスト全体を検索
```

---

*関連ドキュメント: [基本設定ガイド](basic-config.md) | [日常運用手順書](../operation/daily-operation.md)*
