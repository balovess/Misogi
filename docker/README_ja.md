[English](README.md) | [日本語](README_ja.md)

# Misogi (禊) — Docker デプロイメントガイド

Docker および Docker Compose による Misogi のビルド、デプロイ、設定、運用、トラブルシューティングの完全リファレンス。

---

## 目次

1. [概要とアーキテクチャ](#1-概要とアーキテクチャ)
2. [前提条件](#2-前提条件)
3. [クイックスタート](#3-クイックスタート)
4. [ビルドリファレンス](#4-ビルドリファレンス)
5. [docker-compose.yml 完全リファレンス](#5-docker-composeyml-完全リファレンス)
6. [環境変数リファレンス](#6-環境変数リファレンス)
7. [API エンドポイント](#7-api-エンドポイント)
8. [ボリュームとデータ管理](#8-ボリュームとデータ管理)
9. [ネットワークガイド](#9-ネットワークガイド)
10. [セキュリティ強化（本番チェックリスト）](#10-セキュリティ強化本番チェックリスト)
11. [運用とモニタリング](#11-運用とモニタリング)
12. [トラブルシューティング](#12-トラブルシューティング)
13. [高度なデプロイメントパターン](#13-高度なデプロイメントパターン)

---

## 1. 概要とアーキテクチャ

### Misogi とは？

Misogi（禊ぎ）は、クロスネットワーク**セキュアファイル転送システム**であり、組み込みの
**コンテンツ・ディザーム＆リコンストラクション（CDR）**サニタイズ機能を備えています。
日本の政府機関／企業環境での LGWAN 準拠、個人情報（PII）検出、PPAP 排除、監査トレース級ロギング
要件に対応するよう設計されています。

システムは 2 つのノードで構成されます：

| ノード | バイナリ | 役割 | デフォルトポート |
|-------|----------|------|------------------|
| **Sender（送信者）** | `misogi-sender` | ファイルアップロード、CDR サニタイズ、転送開始 | 3001 (HTTP), gRPC |
| **Receiver（受信者）** | `misogi-receiver` | ファイル受信、チャンク再構築、保存 | 3002 (HTTP), 9000 (tunnel) |

### Docker デプロイメントトポロジー

```
                        ┌─────────────────────────────────────┐
                        │         Docker ホスト               │
                        │                                     │
   ホスト ──:3001────────┤  ┌──────────────┐                  │
                        │  │   sender     │  misogi-sender    │
   ホスト ──:3002────────┤  │  :3001        │                   │
                        │  └──────┬───────┘                  │
   ホスト ──:9000────────┤         │ misogi-net (bridge)       │
                        │  ┌──────┴───────┐                  │
                        │  │   receiver   │  misogi-receiver  │
                        │  │  :3002 :9000 │                   │
                        │  └──────────────┘                  │
                        │                                     │
                        │  ボリューム:                            │
                        │  ├── sender_uploads → /data/uploads │
                        │  ├── sender_staging → /data/staging │
                        │  ├── receiver_chunks → /data/chunks │
                        │  └── receiver_downloads → /data/...  │
                        └─────────────────────────────────────┘
```

### マルチステージビルドアーキテクチャ

```
┌─────────────────────────────────────────────────────────────────┐
│ ステージ 1: Builder (rust:1.85-slim)                              │
│                                                                 │
│   • protobuf-compiler をインストール (tonic-build 用)            │
│   • ワークスペースソース + Cargo.toml/Cargo.lock をコピー        │
│   • cargo build --release --workspace                           │
│   • 出力: target/release/{misogi-sender,misogi-receiver}        │
│                                                                 │
│   サイズ: ~2 GB (ビルドキャッシュ) — ビルド後破棄                │
├─────────────────────────────────────────────────────────────────┤
│ ステージ 2: Runtime (debian:bookworm-slim)                        │
│                                                                 │
│   • ca-certificates + curl をインストール (ヘルスチェック用)     │
│   • 非rootユーザー 'misogi' を作成                               │
│   • Builder からコンパイル済みバイナリのみをコピー                │
│   • /data 配下にデータディレクトリを設定                          │
│                                                                 │
│   最終イメージサイズ: ~80 MB                                      │
└─────────────────────────────────────────────────────────────────┘
```

### ベースイメージ選定理由

| ステージ | イメージ | 理由 |
|---------|----------|------|
| Builder | `rust:1.85-slim` | 公式 Rust ツールチェーン（`cargo`, `rustc` 内包）；slim 版はドキュメント除外で約 200 MB 節約 |
| Runtime | `debian:bookworm-slim` | 最小 glibc 系ディストリビューション（ベース約 30 MB）；Rust のデフォルト glibc リンク互換；拡張性のためパッケージ豊富 |

---

## 2. 前提条件

| 要件 | 最小バージョン | 備考 |
|------|----------------|------|
| Docker Engine | ≥ 24.0 | マルチステージビルドサポート必須 |
| Docker Compose | V2 (`docker compose` サブコマンド) | レガシー `docker-compose` Python パッケージではありません |
| ディスク容量（ビルド） | ≥ 4 GB 空き | Rust ツールチェーン + 依存関係 + コンパイルアーティファクト |
| メモリ（ビルド） | ≥ 2 GB 推奨 | Cargo 並列コンパイルはメモリ消費が大きい |
| CPU | 2 コア以上推奨 | ワークスペースは 5 クレート；並列化でビルド高速化 |

### OS 互換性

| OS | ステータス | 備考 |
|----|-----------|------|
| Linux (x86_64/aarch64) | ✅ 完全サポート | ネイティブ Docker パフォーマンス |
| macOS (Apple Silicon / Intel) | ✅ 完全サポート | ファイルシステムレイヤーによりビルドが遅くなる場合あり |
| Windows (WSL2) | ✅ 推奨 | WSL2 バックエンド使用で最適なパフォーマンス |
| Windows (Hyper-V) | ⚠️ サポート済み | 小さなファイル多数の場合ボリュームパフォーマンス低下の可能性あり |

---

## 3. クイックスタート

動作する Misogi デプロイメントまでの 3 コマンド：

```bash
# ステップ 1: リポジトリをクローン
git clone https://github.com/your-org/misogi.git
cd misogi

# ステップ 2: （任意）設定をカスタマイズ
cp docker/env.example .env
# .env を設定で編集（完全な変数リストはセクション 6 を参照）

# ステップ 3: 両サービスをビルドして起動
docker compose up -d --build
```

### デプロイメント確認

```bash
# 両コンテナが稼働中か確認
docker compose ps

# 期待される出力:
# NAME            IMAGE       STATUS                    PORTS
# misogi-sender   misogi      Up (healthy)              0.0.0.0:3001->3001/tcp
# misogi-receiver misogi      Up (healthy)              0.0.0.0:3002->3002/tcp, 0.0.0.0:9000->9000/tcp

# ヘルスエンドポイント確認
curl http://localhost:3001/api/v1/health
# {"status":"ok","role":"sender"}

curl http://localhost:3002/api/v1/health
# {"status":"ok","role":"receiver"}

# 両サービスのログを表示
docker compose logs -f
```

### 個別サービス起動

```bash
# Sender のみ（アップロードエンドポイント）
docker compose up -d sender

# Receiver のみ（ダウンロードエンドポイント）
docker compose up -d receiver
```

---

## 4. ビルドリファレンス

### 手動ビルドコマンド

```bash
# デフォルト release プロファイルでビルド
docker build -t misogi .

# カスタムタグ付き、キャッシュなし（クリーンリビルド）
docker build --no-cache -t misogi:v0.1.0 .

# debug プロファイルでビルド（バイナリ小、トラブルシューティング用）
docker build --build-arg BUILD_PROFILE=debug -t misogi:debug .

# 特定プラットフォーム向けにクロスコンパイル
docker build --platform linux/amd64 -t misogi:amd64 .
docker build --platform linux/arm64 -t misogi:arm64 .
```

### ビルド引数

| 引数 | デフォルト | 説明 |
|------|-----------|------|
| `BUILD_PROFILE` | `release` | Cargo プロファイル（`release` または `debug`）。開発時は `debug` でビルド高速化。 |

### ビルドキャッシュ戦略

Docker レイヤーはコンテンツハッシュでキャッシュされます。以下の順序でキャッシュミスを最小化します：

```
レイヤー 1: apt-get install protoc (ほぼ変更なし)           ← キャッシュ済
レイヤー 2: COPY Cargo.toml Cargo.lock (依存更新時のみ変更) ← キャッシュ済
レイヤー 3: COPY crates/ (コード編集時のみ再ビルド)          ← 再ビルド
レイヤー 4: cargo build (レイヤー 2+3 に依存)              ← 再ビルド
```

**完全リビルド強制**: `docker build --no-cache`

**依存関係レイヤーのみ無効化**: `Cargo.toml` に変更を加えるか `Cargo.lock` を更新

### Builder ステージで `protoc` が必要な理由

[`misogi-core/build.rs`](../crates/misogi-core/build.rs) は `tonic_build::compile_protos()` を呼び出し、
[`proto/file_transfer.proto`](../crates/misogi-core/proto/file_transfer.proto) を Rust ソースコードに
コンパイルするために Protocol Buffer コンパイラ（`protoc`）をビルド時に必要とします。
`protobuf-compiler` がない場合、ビルドは以下のエラーで失敗します：

```
error: failed to run custom build command for `misogi-core` (v0.1.0)
Caused by: could not find protocol compiler
```

---

## 5. docker-compose.yml 完全リファレンス

### サービス: sender

| フィールド | 値 | 説明 |
|-----------|-----|------|
| `image` | `misogi:latest` | プロジェクト Dockerfile からローカルビルド |
| `container_name` | `misogi-sender` | 固定名により一貫した `docker exec` アクセスを確保 |
| `restart` | `unless-stopped` | クラッシュ時またはホスト再起動時に自動再起動；手動停止は尊重 |
| `entrypoint` | `misogi-sender` | Dockerfile デフォルトを上書き（同じ値、明示的記述） |
| `command` | `--mode server` | HTTP API サーバーとして実行（デーモンモードではない） |
| `ports` | `${SENDER_PORT:-3001}:3001` | ホストポート 3001（.env で設定可能）をコンテナポート 3001 にマッピング |
| `volumes` | `sender_uploads:/data/uploads` | アップロードファイルをコンテナ再起動間で永続化 |
| `volumes` | `sender_staging:/data/staging` | CDR 処理中のファイルを再起動間で永続化 |
| `healthcheck.test` | `curl -f http://localhost:3001/api/v1/health` | ヘルスエンドポイントへの HTTP GET |
| `healthcheck.interval` | 30s | 30 秒ごとにポーリング |
| `healthcheck.timeout` | 5s | 応答 > 5 秒で失敗判定 |
| `healthcheck.retries` | 3 | 連続 3 回失敗で unhealthy マーク |
| `healthcheck.start_period` | 10s | ヘルスチェックが retries にカウントされる前の猶予期間 |
| `networks` | `misogi-net` | コンテナ間通信のための共有ブリッジネットワークに参加 |

### サービス: receiver

| フィールド | 値 | 説明 |
|-----------|-----|------|
| `ports` | `${RECEIVER_PORT:-3002}:3002` | Receiver HTTP API |
| `ports` | `${TUNNEL_PORT:-9000}:9000` | Sender 接続用のリバーストンネルリスナー |
| `volumes` | `receiver_chunks:/data/chunks` | 軸送中の受信チャンク格納 |
| `volumes` | `receiver_downloads:/data/downloads` | 完了したダウンロード格納 |
| `healthcheck.test` | `curl -f http://localhost:3002/api/v1/health` | Sender と同パターン、ポート異なる |

### ボリューム

| ボリューム名 | コテナパス | 内容 | 永続性 |
|-------------|------------|------|--------|
| `sender_uploads` | `/data/uploads` | 処理待ちアップロードファイル | 名前付きボリューム（再作成で生存） |
| `sender_staging` | `/data/staging` | CDR サニタイズ処理中のファイル | 名前付きボリューム（再作成で生存） |
| `receiver_chunks` | `/data/chunks` | 軸送中の受信チャンク | 名前付きボリューム（再作成で生存） |
| `receiver_downloads` | `/data/downloads` | 完了・再構築済みファイル | 名前付きボリューム（再作成で生存） |

### ネットワーク

| ネットワーク | ドライバー | 用途 |
|-------------|-----------|------|
| `misogi-net` | bridge | Sender ↔ Receiver 間通信用の分離 L2 ネットワーク |

### スケーラビリティに関する考慮事項

- **複数 Sender**: 可能。ロードバランサーの背後に複数 Sender インスタンスを展開できます。各 Sender は独自のアップロード状態を維持します。
- **複数 Receiver**: 部分的にサポート。各 Receiver インスタンスは独立したチャンク/ダウンロードストレージを持ちます。状態の一貫性には名前付きボリュームまたは外部 NFS/S3 バックエンドを使用してください。
- **共通イメージ**: 両サービスは両バイナリを含む同一の `misogi:latest` イメージを使用します。個別イメージ不要です。

---

## 6. 環境変数リファレンス

### 優先順位

設定解決は以下の優先順位チェーンに従います（上位が勝利）：

```
CLI 引数 (--flag)                  # 最高優先順位
    ↓
環境変数 (MISOGI_*)                # docker compose env / docker run -e
    ↓
Dockerfile ENV デフォルト         # イメージに組み込み
    ↓
アプリケーション組み込みデフォルト   # config.rs Default impl にハードコード
```

`docker compose` 使用時、`.env` ファイル値が `docker-compose.yml` デフォルトを上書きします：

```
.env ファイル > docker-compose.yml ${VAR:-default} > Dockerfile ENV > アプリデフォルト
```

### 共通変数

| 変数 | デフォルト | 説明 | 例 |
|------|-----------|------|-----|
| `MISOGI_LOG_LEVEL` | `info` | トレース詳細度: `trace`, `debug`, `info`, `warn`, `error` | `debug` |
| `RUST_LOG` | `info` | Rust トレーシングサブスクライバフィルタ（MISOGI_LOG_LEVEL より詳細な場合上書き） | `misogi_sender=trace,tower_http=debug` |
| `MISOGI_LOG_FORMAT` | `json` | 監査ログ形式: `json`, `syslog`, `cef`, `custom` | `cef` |

### Sender 専用変数

| 変数 | デフォルト | 説明 | 例 |
|------|-----------|------|-----|
| `MISOGI_SERVER_ADDR` | `0.0.0.0:3001` | HTTP バインドアドレス | `0.0.0.0:8080` |
| `MISOGI_UPLOAD_DIR` | `/data/uploads` | アップロードファイル格納ディレクトリ | `/mnt/nfs/uploads` |
| `MISOGI_STAGING_DIR` | `/data/staging` | CDR 処理ステージングエリア | `/mnt/nfs/staging` |
| `MISOGI_TRANSFER_DRIVER_TYPE` | `direct_tcp` | 転送バックエンド: `direct_tcp`, `storage_relay`, `external_command` | `storage_relay` |
| `MISOGI_TUNNEL_REMOTE_ADDR` | *(空)* | リモートトンネルサーバーアドレス | `relay.example.com:9000` |
| `MISOGI_TUNNEL_AUTH_TOKEN` | *(空)* | トンネル認証トークン | `secret-token-abc123` |
| `MISOGI_PII_ENABLED` | `false` | アップロード時の PII スキャン有効化 | `true` |
| `MISOGI_VENDOR_ISOLATION_ENABLED` | `false` | マルチテナントベンダー分離有効化 | `true` |
| `MISOGI_SENDER_DRIVER_TYPE` | `direct_tcp` | Compose 専用 MISOGI_TRANSFER_DRIVER_TYPE エイリアス（sender サービス用） | `storage_relay` |

### Receiver 専用変数

| 変数 | デフォルト | 説明 | 例 |
|------|-----------|------|-----|
| `MISOGI_SERVER_ADDR` | `0.0.0.0:3002` | HTTP バインドアドレス（receiver コンテキスト） | `0.0.0.0:8080` |
| `MISOGI_CHUNK_DIR` | `/data/chunks` | 受信転送チャンク格納ディレクトリ | `/mnt/nfs/chunks` |
| `MISOGI_DOWNLOAD_DIR` | `/data/downloads` | 完了ダウンロード格納ディレクトリ | `/mnt/nfs/downloads` |
| `MISOGI_RECEIVER_DRIVER_TYPE` | `direct_tcp` | 転送バックエンド: `direct_tcp`, `storage_relay` | `storage_relaw` |
| `MISOGI_TUNNEL_AUTH_TOKEN` | *(空)* | トンネル認証トークン（sender と一致必須） | `secret-token-abc123` |

### Compose ポート上書き変数

| 変数 | デフォルト | 対応先 |
|------|-----------|--------|
| `SENDER_PORT` | `3001` | Sender HTTP API のホストポート |
| `RECEIVER_PORT` | `3002` | Receiver HTTP API のホストポート |
| `TUNNEL_PORT` | `9000` | Receiver トンネルリスナーのホストポート |

### クイック設定テンプレート

コピーしてカスタマイズ：

```bash
cp docker/env.example .env
```

`.env` を編集：

```env
# 本番環境例
MISOGI_LOG_LEVEL=warn
RUST_LOG=misogi_sender=info
MISOGI_LOG_FORMAT=cef
MISOGI_PII_ENABLED=true
SENDER_PORT=3001
RECEIVER_PORT=3002
TUNNEL_PORT=9000
MISOGI_SENDER_DRIVER_TYPE=direct_tcp
MISOGI_TUNNEL_REMOTE_ADDR=
```

---

## 7. API エンドポイント

すべてのエンドポイントは JSON を返します。CORS はデフォルトで許容的に有効化されています。
すべてのレスポンスに `X-Request-ID` ヘッダーが含まれ、リクエスト追跡に使用できます。

### Sender API — ポート 3001

| メソッド | パス | 説明 | リクエストボディ | 例 |
|----------|------|------|------------------|-----|
| `POST` | `/api/v1/upload` | ファイルアップロード (multipart) | `multipart/form-data: file` | `curl -F "file=@doc.pdf" http://localhost:3001/api/v1/upload` |
| `GET` | `/api/v1/files` | アップロードファイル一覧 | クエリ: `?page=1&per_page=20&status=ready` | `curl 'http://localhost:3001/api/v1/files?page=1&per_page=10'` |
| `GET` | `/api/v1/files/:file_id` | ファイルメタデータ取得 | — | `curl http://localhost:3001/api/v1/files/abc-123` |
| `POST` | `/api/v1/files/:file_id` | Receiver への転送トリガー | — | `curl -X POST http://localhost:3001/api/v1/files/abc-123` |
| `POST` | `/api/v1/sanitize/:file_id` | 手動 CDR サニタイズ実行 | — | `curl -X POST http://localhost:3001/api/v1/sanitize/abc-123` |
| `GET` | `/api/v1/sanitize/policies` | 利用可能な CDR ポリシー一覧 | — | `curl http://localhost:3001/api/v1/sanitize/policies` |
| `GET` | `/api/v1/health` | ヘルスチェックプローブ | — | `curl http://localhost:3001/api/v1/health` |
| `POST` | `/api/v1/transfers` | 承認必要転送を作成 | JSON ボディ | `curl -X POST -H "Content-Type: application/json" -d '{"file_id":"..."}' http://localhost:3001/api/v1/transfers` |
| `GET` | `/api/v1/transfers` | 全転送一覧 | — | `curl http://localhost:3001/api/v1/transfers` |
| `GET` | `/api/v1/transfers/pending` | 承認待ち一覧 | — | `curl http://localhost:3001/api/v1/transfers/pending` |
| `GET` | `/api/v1/transfers/:request_id` | 転送詳細取得 | — | `curl http://localhost:3001/api/v1/transfers/req-001` |
| `POST` | `/api/v1/transfers/:request_id/approve` | 承認待ち転送を承認 | — | `curl -X POST http://localhost:3001/api/v1/transfers/req-001/approve` |
| `POST` | `/api/v1/transfers/:request_id/reject` | 承認待ち転送を拒否 | — | `curl -X POST http://localhost:3001/api/v1/transfers/req-001/reject` |
| `POST` | `/api/v1/ppap/detect` | PPAP 指標のファイルスキャン | `multipart/form-data: file` | `curl -F "file=@archive.zip" http://localhost:3001/api/v1/ppap/detect` |

#### 主要レスポンス例

**アップロードレスポンス:**
```json
{
  "file_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "ready",
  "filename": "report.pdf",
  "total_size": 1048576,
  "chunk_count": 1
}
```

**ヘルスレスポンス:**
```json
{"status": "ok", "role": "sender"}
```

### Receiver API — ポート 3002

| メソッド | パス | 説明 | 例 |
|----------|------|------|-----|
| `GET` | `/api/v1/files` | 受信ファイル一覧 | `curl http://localhost:3002/api/v1/files` |
| `GET` | `/api/v1/download/:file_id` | 完了ファイルダウンロード (バイナリ) | `curl -o output.pdf http://localhost:3002/download/abc-123` |
| `GET` | `/api/v1/files/:file_id/status` | ファイルの転送ステータス取得 | `curl http://localhost:3002/api/v1/files/abc-123/status` |
| `POST` | `/api/v1/files/:file_id/reassemble` | チャンクから手動で最終ファイルを再構築 | `curl -X POST http://localhost:3002/api/v1/files/abc-123/reassemble` |
| `GET` | `/api/v1/health` | ヘルスチェックプローブ | `curl http://localhost:3002/api/v1/health` |

**ヘルスレスポンス:**
```json
{"status": "ok", "role": "receiver"}
```

---

## 8. ボリュームとデータ管理

### コンテナ内ボリュームレイアウト

```
/data/
├── uploads/     ← sender: ユーザーアップロード (CDR 前)
├── staging/     ← sender: CDR パイプライン処理中のファイル
├── chunks/      ← receiver: 軉送中の受信チャンク
└── downloads/   ← receiver: 完了・再構築済み出力ファイル
```

### ボリューム内容の確認

```bash
# Compose 作成名前付きボリューム一覧
docker volume ls | grep misogi

# ボリューム詳細確認（マウントポイント、ドライバー等）
docker volume inspect misogi_sender_uploads

# ボリューム内ファイル参照（読み取り専用マウントで一時コンテナ使用）
docker run --rm -v misogi_sender_uploads:/data busybox ls -la /data/

# 対話型ブラウザ
docker run --rm -it -v misogi_sender_uploads:/data busybox sh
```

### バックアップ手順

```bash
# 全 Misogi ボリュームのバックアップアーカイブ作成
docker run --rm \
  -v misogi_sender_uploads:/src/uploads \
  -v misogi_sender_staging:/src/staging \
  -v misogi_receiver_chunks:/src/chunks \
  -v misogi_receiver_downloads:/src/downloads \
  -v $(pwd):/backup \
  alpine tar czf /backup/misogi-data-backup-$(date +%Y%m%d).tar.gz -C /src .
```

### 復元手順

```bash
# 先にサービス停止
docker compose down

# 新規ボリュームにバックアップ抽出
docker run --rm \
  -v misogi_sender_uploads:/dst/uploads \
  -v misogi_sender_staging:/dst/staging \
  -v misogi_receiver_chunks:/dst/chunks \
  -v misogi_receiver_downloads:/dst/downloads \
  -v $(pwd):/backup \
  alpine sh -c "tar xzf /backup/misogi-data-backup-YYYYMMDD.tar.gz -C /dst"

# 再起動
docker compose up -d
```

### 名前付きボリュームの代わりに Bind Mount 使用

開発時やホストファイルシステムへの直接アクセスが必要な場合、`docker-compose.yml` を変更：

```yaml
# 置換:
#   - sender_uploads:/data/uploads
# 以下へ:
  - ./data/sender/uploads:/data/uploads
```

**トレードオフ**: Bind Mount はホスト権限を保持しますが、ディレクトリ自動初期化は行いません。名前付きボリュームは Docker が完全に管理し、コンテナ再作成で存続します。

### データライフサイクル

| コマンド | ボリュームへの影響 |
|---------|-------------------|
| `docker compose down` | コンテナ停止；**ボリュームは保持** |
| `docker compose down -v` | コンテナ停止；**ボリュームは永久削除** |
| `docker compose up -d` | コンテナ再作成；**既存ボリュームを再利用** |
| `docker volume prune` | 未使用ボリュームすべて削除（危険） |

> **⚠ 警告**: `docker compose down -v` はバックアップされていない限り永続化されたファイルデータを不可逆的に破棄します。

---

## 9. ネットワークガイド

### デフォルトブリッジネットワーク (`misogi-net`)

両コンテナが同一ブリッジネットワークに参加します。サービス名をホスト名として
相互通信できます：

```
sender コンテナ内から:
  curl http://receiver:3002/api/v1/health    ✅ 動作（同一ネットワーク）

ホストマシンから:
  curl http://localhost:3002/api/v1/health    ✅ 動作（公開ポート経由）
```

### コンテナ間通信

Sender から Receiver への直接 TCP 転送が可能です：

```
sender (misogi-net: 172.x.x.2)
    │
    └──► receiver (misogi-net: 172.x.x.3):3002  (HTTP)
    └──► receiver (misogi-net: 172.x.x.3):9000  (tunnel)
```

`MISOGI_TUNNEL_REMOTE_ADDR` を設定し、Sender が Receiver に到達する方法を指定します：

```env
# コンテナ間通信の場合、サービス名を使用:
MISOGI_TUNNEL_REMOTE_ADDR=receiver:9000
```

### トンネルモード（ポート 9000）

Sender から Receiver へ直接接続できない場合（例：Receiver が NAT 背後にある場合）、
Receiver はポート 9000 に**リバーストンネル**を公開します。Sender はこのトンネルポートに
接続し、トラフィックは内部で転送されます。

```
  Sender                              Receiver
  ┌──────────┐                     ┌────────────┐
  │          │  TCP 接続 ────────►│  :9000     │
  │  :3001   │    to tunnel port   │  (tunnel   │
  │          │ ◄────────────────── │   handler) │
  └──────────┘  forwarded traffic  └────────────┘
```

### カスタムネットワーク設定

本番環境では分離ネットワークが必要な場合があります：

```yaml
# docker-compose.yml に追加:
services:
  sender:
    networks:
      - frontend    # ロードバランサーに :3001 を公開
      - internal    # Receiver と通信

  receiver:
    networks:
      - internal    # Sender からのみアクセス（公開ポート不要）

networks:
  frontend:
    driver: bridge
    # リバースプロキシ統合用外部ネットワークにアタッチ
    # external: true
    # name: proxy_network
  internal:
    driver: bridge
    internal: true  # 外部アクセスなし（インターネットルーティングなし）
```

---

## 10. セキュリティ強化（本番チェックリスト）

### Dockerfile で既に実装済み

- [x] **非 root ユーザー**: コンテナは `misogi`（UID/GID 自動割当て）として実行、root ではない
- [x] **最小ランタイムイメージ**: `debian:bookworm-slim` でフル OS より攻撃面積を低減
- [x] **ヘルスチェック**: 自動 unhealthy コンテナ検出

### 本番環境で推奨される追加措置

#### リソース制限

`docker-compose.yml` の各サービスに追加：

```yaml
services:
  sender:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 128M
  receiver:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 256M
```

#### 読み取り専用ルートファイルシステム

```yaml
services:
  sender:
    read_only: true
    tmpfs:
      - /tmp:size=64M,mode=1777
```

> **注**: アプリケーションは `/data/*`（ボリュームマウント）に書き込みますが、これはルートファイルシステムではありません。読み取り専用 root は偶発的または侵害された場合のシステムパス書き込みを防ぎます。

#### シークレット管理

**本番環境では `.env` にトークンをコミットしないでください**。選択肢：

1. **Docker Secrets** (Swarm モード):
   ```yaml
   environment:
     - MISOGI_TUNNEL_AUTH_TOKEN=/run/secrets/tunnel_token
   secrets:
     - tunnel_token
   ```

2. **外部シークレットストア** (HashiCorp Vault, AWS Secrets Manager):
   実行時に `docker run -e` またはオーケストレーションプラットフォーム経由で注入。

3. **`.env` ファイル（制限付き権限）**（開発のみ）:
   ```bash
   chmod 600 .env
   ```

#### TLS 終端処理（リバースプロキシ）

両サービスの前にリバースプロキシ（nginx / Caddy / Traefik）を配置：

**Caddy 自動 HTTPS 例:**

```
# Caddyfile
file.example.com {
    reverse_proxy misogi-sender:3001
}

download.example.com {
    reverse_proxy misogi-receiver:3002
}
```

**nginx 例:**

```nginx
server {
    listen 443 ssl;
    server_name file.example.com;

    ssl_certificate     /etc/ssl/certs/misogi.crt;
    ssl_certificate_key /etc/ssl/private/misogi.key;

    location / {
        proxy_pass http://misogi-sender:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

リバースプロキシを `misogi-net` ネットワークに接続：

```yaml
# docker-compose.yml の networks に追加:
networks:
  misogi-net:
    external: false
    # 既存プロキシネットワークにアタッチ:
    # external: true
    # name: your_proxy_network
```

#### ログ集約

Docker はデフォルトで stdout/stderr をキャプチャします。本番環境用にログドライバーを設定：

```yaml
services:
  sender:
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
  receiver:
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
```

集中ログの場合、`fluentd`、`syslog`、または `awslogs` ドライバーに切り替え。

---

## 11. 運用とモニタリング

### ログの表示

```bash
# 全サービス、tail 表示
docker compose logs -f

# 単一サービス
docker compose logs -f sender
docker compose logs -f receiver

# 直近 N 行
docker compose logs --tail=100 sender

# タイムスタンプ付与
docker compose logs -t -f

# ログレベルフィルタ（アプリケーションは JSON ログを出力）
docker compose logs sender | grep '"level":"error"'
```

### ヘルスチェック解釈

| 状態 | 意味 | 対策 |
|------|------|------|
| `healthy` | `/api/v1/health` にタイムアウト内で応答 | 正常稼働 |
| `unhealthy` | 連続 3 回のヘルスチェック失敗 | ログ確認: `docker compose logs sender` |
| `starting` | `start_period` 猶予期間内（10秒） | 待機; まだ評価対象外 |

```bash
# 現在のヘルスステータス確認
docker inspect --format='{{.State.Health.Status}}' misogi-sender
```

### 再起動動作

ポリシー: `unless-stopped`

| イベント | 動作 |
|---------|------|
| コンテナクラッシュ | 即座に自動再起動 |
| Docker デーモン再起動 | デーモン復帰時に自動再起動 |
| 手動 `docker compose stop` | 停止状態継持（`up` まで自動再起動なし） |
| `docker compose down` | 削除（再度 `up` で起動必要） |

### グレイスフルシャットダウン

両サービスは SIGTERM（`docker stop` から送信）を適切に処理します：

1. HTTP サーバーが新規接続の受付を停止
2. 進行中のリクエストが完了（Docker のデフォルト 10 秒猶予まで）
3. 転送タスクにキャンセル信号送信
4. プロセスがクリーンに終了

```bash
# グレイスフル停止（進行中作業を待機、デフォルト 10 秒タイムアウト）
docker compose stop

# 強制終了（即時、進行中データ損失の可能性あり）
docker compose kill
```

### リソースモニタリング

```bash
# リアルタイムリソース使用量
docker stats

# 単一コンテナ
docker stats misogi-sender --no-stream
```

### ゼロダウンフリー再デプロイ

```bash
# 単一サービスを再ビルド・再デプロイ（ダウンタイムなし）
docker compose up -d --build --no-deps sender

# これにより: 新規イメージビルド → 古いコンテナ停止 → 新規コンテナ起動
# 前にロードバランサーがある場合、接続をグレイスフルにドレインします。
```

### スケールアウト

**1 つの Sender に複数の Receiver を配置:**

```bash
# Receiver を 3 インスタンスにスケール
docker compose up -d --scale receiver=3
```

> **注**: 各 Receiver インスタンスは匿名ボリュームを取得します。共有ストレージには名前付きボリュームまたは外部 NFS/S3 バックエンドを `MISOGI_DOWNLOAD_DIR` で設定してください。

---

## 12. トラブルシューティング

### コンテナが起動しない

**症状:** `docker compose ps` でステータス `Exited` または `Restarting` を表示。

**診断:**

```bash
# コンテナ終了コード確認
docker compose ps -a

# 起動ログ表示
docker compose logs sender

# 一般的原因:
# 1. ポート既に使用中:
#    Error: address already in use 0.0.0.0:3001
#    対策: .env で SENDER_PORT を変更、または競合プロセスを停止

# 2. ボリューム権限拒否（名前付きボリュームでは稀）:
#    対策: docker compose down -v && docker compose up -d

# 3. 不正な環境変数形式:
#    対策: .env 構文を検証（= の前後にスペースなし）
```

### ビルド失敗

**症状:** `docker build` が非ゼロコードで終了。

**一般的な原因:**

```bash
# 1. protoc 未検出（Dockerfile にあれば発生しないはず）
#    "could not find protocol compiler" が表示された場合
#    対策: Dockerfile 行 21 に `protobuf-compiler` があることを確認

# 2. ディスク容量不足（コンパイル中）
#    Error: "no space left on device"
#    対策: docker system prune -af（ビルドキャッシュ解放）

# 3. Rust コンパイルエラー（コード問題）
#    対策: コンパイラ出力を確認; 先にローカルで `cargo build` でテスト

# 4. Cargo.lock 欠落（依存関係解決不一致）
#    対策: .dockerignore が Cargo.lock を除外していないことを確認
```

### ヘルスチェック失敗

**症状:** コンテナは稼働しているがステータスが `(unhealthy)` を表示。

**診断:**

```bash
# コンテナ内から手動でヘルスエンドポイントをテスト
docker compose exec sender curl -f http://localhost:3001/api/v1/health

# PATH に curl がない場合:
docker compose exec sender /usr/bin/curl -f http://localhost:3001/api/v1/health

# それでも動作するのに Docker ヘルスチェックが失敗する場合:
# - ヘルスチェックタイミング: サービスにより長い start_period が必要
# - MISOGI_SERVER_ADDR が公開ポートと一致することを確認
```

### ファイルアップロード失敗

**症状:** `POST /api/v1/upload` が 500 エラーを返す。

**診断:**

```bash
# コンテナ内ボリュームの空き容量確認
docker compose exec sender df -h /data/uploads

# ボリュームが書き込み可能か確認
docker compose exec sender touch /data/uploads/.test_write && \
  docker compose exec sender rm /data/uploads/.test_write

# I/O エラーの sender ログを確認
docker compose logs --tail=50 sender | grep -i error
```

### Sender から Receiver に到達できない

**症状:** 転送がトリガーされたが `transferring` ステータスのまま永遠に停止。

**診断:**

```bash
# 両コンテナが同一ネットワークにいるか確認
docker network inspect misogi_net

# Sender から Receiver への接続性をテスト
docker compose exec sender wget -qO- http://receiver:3002/api/v1/health
# または:
docker compose exec sender curl -f http://receiver:3002/api/v1/health

# トンネルモード使用時、ポート 9000 がアクセス可能か確認
docker compose exec sender nc -zv receiver 9000
```

### デバッグモード

詳細ログを有効にして問題をトレース：

```env
# .env に追加:
MISOGI_LOG_LEVEL=debug
RUST_LOG=misogi_sender=trace,misogi_core=debug,tower_http=debug
```

その後:

```bash
docker compose up -d  # 新規 env var で再起動
docker compose logs -f sender | head -100
```

### デバッグ用シェルアクセス

```bash
# 稼働中コンテナ内で対話型シェルを取得
docker compose exec sender sh

# シェル内でテスト:
# - ネットワーク: wget/curl で他サービス
# - ファイルシステム: ls -la /data/
# - プロセス: ps aux
# - 環境変数: env | grep MISOGI
```

---

## 13. 高度なデプロイメントパターン

### 開発モード（ホットリロード）

迅速な開発反復のため、ソースコードをマウントして `cargo watch` を使用：

```yaml
# docker-compose.dev.yml（オーバーライドファイル）
services:
  sender:
    build:
      context: .
      dockerfile: Dockerfile.dev
    volumes:
      - ./crates/misogi-sender/src:/app/src:ro
      - ./crates/misogi-core/src:/app/core_src:ro
      - ./crates/misogi-cdr/src:/app/cdr_src:ro
      - ./target:/app/target
    environment:
      - MISOGI_LOG_LEVEL=debug
      - RUST_LOG=misogi_sender=trace
    command: ["cargo", "watch", "-x", "run", "--bin", "misogi-sender", "--", "--mode", "server"]

# 使用方法:
# docker compose -f docker-compose.yml -f docker-compose.dev.yml up sender
```

### エアギャップデプロイメント（ストレージリレー模式）

Sender と Receiver に **TCP 接続がない** ネットワークの場合、`storage_relay` ドライバーを
共有ディレクトリと併用:

```yaml
# docker-compose.airgapped.yml
services:
  sender:
    environment:
      - MISOGI_SENDER_DRIVER_TYPE=storage_relay
      - MISOGI_TRANSFER_OUTPUT_DIR=/shared/outbound
    volumes:
      - relay_shared:/shared

  receiver:
    environment:
      - MISOGI_RECEIVER_DRIVER_TYPE=storage_relay
      - MISOGI_TRANSFER_INPUT_DIR=/shared/inbound
    volumes:
      - relay_shared:/shared

volumes:
  relay_shared:
    driver: local

# 使用方法:
# docker compose -f docker-compose.yml -f docker-compose.airgapped.yml up -d
#
# フロー:
# 1. Sender がファイルマニフェストを /shared/outbound/ に格納
# 2. Receiver が /shared/inbound/ を新しいマニフェストでポーリング
# 3. ファイルは共有ボリューム経由で転送、ネットワーク不要
```

### 外部コマンドドライバー統合

組織で義務付けられたセキュア転送ツール（例：政府ゲートウェイ）を使用する場合、
外部コマンドとして設定:

```yaml
services:
  sender:
    environment:
      - MISOGI_SENDER_DRIVER_TYPE=external_command
    volumes:
      - /usr/local/bin/secure-transfer-tool:/usr/local/bin/secure-transfer-tool:ro
    # 外部コマンドは読み取り専用でコンテナにマウントする必要があります
```

対応する TOML 設定（env vars ではなく config file 使用時）:

```toml
[transfer_driver]
type = "external_command"
send_command = "/usr/local/bin/secure-transfer-tool send --input %s --dest %d"
status_command = "/usr/local/bin/secure-transfer-tool status %s"
timeout_secs = 120
```

### Kubernetes 移行

`docker-compose.yml` の概念を Kubernetes マニフェストに変換:

```yaml
# k8s/deployment-sender.yaml (抜粋)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: misogi-sender
spec:
  replicas: 2
  selector:
    matchLabels:
      app: misogi-sender
  template:
    metadata:
      labels:
        app: misogi-sender
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 9999
      containers:
      - name: sender
        image: misogi:latest
        ports:
        - containerPort: 3001
        env:
        - name: MISOGI_SERVER_ADDR
          value: "0.0.0.0:3001"
        - name: MISOGI_UPLOAD_DIR
          value: "/data/uploads"
        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: 3001
          initialDelaySeconds: 10
          periodSeconds: 30
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
        volumeMounts:
        - name: uploads
          mountPath: /data/uploads
      volumes:
      - name: uploads
        persistentVolumeClaim:
          claimName: misogi-uploads-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: misogi-sender-service
spec:
  selector:
    app: misogi-sender
  ports:
  - port: 3001
    targetPort: 3001
  type: ClusterIP
```

### CI/CD パイプライン例（GitHub Actions）

```yaml
# .github/workflows/docker-ci.yml
name: Docker CI/CD

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Docker イメージをビルド
        run: docker build -t misogi:${{ github.sha }} .

      - name: サービスを起動
        run: docker compose up -d

      - name: ヘルスチェック
        run: |
          for i in {1..30}; do
            if curl -sf http://localhost:3001/api/v1/health > /dev/null && \
               curl -sf http://localhost:3002/api/v1/health > /dev/null; then
              echo "✅ 両サービス正常"
              exit 0
            fi
            echo "待機中... ($i/30)"
            sleep 2
          done
          echo "❌ ヘルスチェックタイムアウト"
          docker compose logs
          exit 1

      - name: インテグレーションテストを実行
        run: |
          # テストファイルをアップロード
          UPLOAD=$(curl -s -F "file=@README.md" http://localhost:3001/api/v1/upload)
          echo "アップロードレスポンス: $UPLOAD"

          # file_id を抽出し、一覧確認
          FILE_ID=$(echo "$UPLOAD" | jq -r '.file_id')
          curl -sf "http://localhost:3001/api/v1/files/$FILE_ID" | jq .

      - name: レジストリにプッシュ (main ブランチのみ)
        if: github.ref == 'refs/heads/main'
        run: |
          echo "${{ secrets.REGISTRY_PASSWORD }}" | docker login ghcr.io -u "${{ github.actor }}" --password-stdin
          docker tag misogi:${{ github.sha }} ghcr.io/${{ github.repository }}:latest
          docker push ghcr.io/${{ github.repository }}:latest

      - name: クリーンアップ
        if: always()
        run: docker compose down -v
```

### ゼロトラストアーキテクチャデプロイメント（G-Cloud ネイティブ）

デジタル庁の **ゼロトラストアーキテクチャ（ZTA）** への 2030 年までの移行を進める組織向けに、
Misogi は Government Cloud（G-Cloud）と整合したクラウドネイティブデプロイメントパターンを提供します。

```yaml
# docker-compose.zta.yml（G-Cloud デプロイメント）
services:
  sender:
    environment:
      - MISOGI_SENDER_DRIVER_TYPE=grpc_web
      - MISOGI_PII_ENABLED=true
      - MISOGI_VENDOR_ISOLATION_ENABLED=true
      - MISOGI_PRESET=digital_agency_zt
    volumes:
      - sender_uploads:/data/uploads
      - sender_staging:/data/staging
  receiver:
    environment:
      - MISOGI_RECEIVER_DRIVER_TYPE=grpc_web
      - MISOGI_TUNNEL_AUTH_TOKEN=${ZTA_TUNNEL_TOKEN}
    volumes:
      - receiver_chunks:/data/chunks
      - receiver_downloads:/data/downloads
networks:
  zta-net:
    driver: bridge
    internal: false
# 使用方法:
# docker compose -f docker-compose.yml -f docker-compose.zta.yml up -d
#
# フロー:
# 1. Sender: gRPC-Web（ブラウザ → K8s Receiver、サーバーサイドファイル転送なし）
# 2. Receiver: gRPC-Web サーバー（ブラウザクライアント用 Envoy プロキシ）
# 3. OIDC: G-Cloud IdP（Keycloak/Azure AD）との統一認証
# 4. WASM: オプション: ブラウザサイド CDR（ゼロノレッジ処理）
```

**有効化される主な ZTA 機能:**
- **gRPC-Web**: ブラウザ → K8s 直接通信（HTTP アップロード/ダウンロードをバイパス）
- **OIDC 統合**: G-Cloud ID プロバイダーによるシングルサインオン
- **ベンダー分離**: 外部請負業者向けマルチテナントアクセス制御
- **ZTA プリセット**: `digital_agency_zt` プロファイル（[`misogi-core::presets`](../crates/misogi-core/src/presets.rs) 参照）
  - 厳格なサニタイズ: `ConvertToFlat`（画像のみ PDF）
  - ZIP 深度制限: 1（ZTA はエンドポイント処理を前提）
  - 監査ログ保持期間延長: 7 年（ZTA 要件）
  - 強制承認 + 理由入力（ファイル単位監査トレース）

**移行パス:**
```yaml
# フェーズ 1: ハイブリッド（Sender オンプレミス、Receiver on G-Cloud）
services:
  sender:
    # オンプレミス LGWAN ネットワーク
    environment:
      - MISOGI_SENDER_DRIVER_TYPE=storage_relay
      - MISOGI_TRANSFER_OUTPUT_DIR=/shared/outbound
    volumes:
      - lgwan_storage:/shared
  receiver:
    # G-Cloud デプロイメント
    deploy:
      replicas: 2
    environment:
      - MISOGI_RECEIVER_DRIVER_TYPE=grpc_web
# フェーズ 2: 完全 ZTA（両方 G-Cloud 上）
# 上記 docker-compose.zta.yml を参照
```

---

## ファイル索引

| ファイル | 用途 |
|--------|------|
| [`Dockerfile`](../Dockerfile) | マルチステージビルド定義 |
| [`docker-compose.yml`](../docker-compose.yml) | サービスオーケストレーション（sender + receiver） |
| [`.dockerignore`](../.dockerignore) | ビルドコンテキスト除外対象 |
| [`docker/env.example`](./env.example) | 環境変数テンプレート（`.env` にコピー） |
| **このファイル** | 完全デプロイメントドキュメント |
