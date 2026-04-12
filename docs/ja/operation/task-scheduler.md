# Windows タスクスケジューラ設定ガイド (Task Scheduler Setup)

Misogi を Windows サービスとして常駐実行させる代わりに、
Windows タスクスケジューラを使用して定期的にファイル監視・転送タスクを実行する方法を解説します。

**対象読者**: システム管理者、運用担当者  
**前提条件**: Misogi のインストールが完了していること

---

## 1. 概要

### 1-1. なぜタスクスケジューラを使用するのか

| 方法 | 利点 | 欠点 |
|------|------|------|
| **サーバーモード (server)** | 常時待ち受け、リアルタイム処理 | リソース常時消費 |
| **デーモンモード (daemon)** | バックグラウンド常駐 | 同上 |
| **タスクスケジューラ** | スケジュール実行、リソース節約 | 処理遅延（ポーリング間隔分） |

タスクスケジューラ方式は以下のシナリオで推奨されます：

- 日次/週次のバッチ転送運用
- リソースを節約したい環境
- 特定の時間帯のみファイル転送を行う場合

---

## 2. タスクの作成（ステップバイステップ）

### Step 1: タスクスケジューラを開く

1. スタートボタンを右クリック
2. 「**コンピューターの管理**」を選択
3. 左ペインで「**タスクスケジューラ**」を展開

> **[スクリーンショット placeholder]**
> コンピューターの管理画面
> 左側のツリーで「システム ツール → タスクスケジューラ」が展開されている状態

または、直接起動：

```powershell
taskschd.msc
```

### Step 2: 基本タスクの作成ウィザードを開始

1. 右ペインの「**基本タスクの作成...**」をクリック

> **[スクリーンショット placeholder]**
> 「基本タスクの作成」ウィザードの最初の画面
> 「名前」「説明」入力フィールドが表示されている

2. 以下の情報を入力：

| 項目 | 入力値 | 説明 |
|------|--------|------|
| 名前 | `Misogi File Watch - Daily` | タスクの一意な名前 |
| 説明 | `Misogi CDR ファイル監視・転送タスク（日次）` | 管理用メモ |

3. 「**次へ**」をクリック

### Step 3: トリガー（実行タイミング）の設定

#### パターン A: 毎日実行（日次バッチ）

> **[スクリーンショット placeholder]**
> 「タスクのトリガー」選択画面
> 「毎日」が選択されている状態

1. 「**毎日**」を選択
2. 「**次へ**」をクリック
3. 以下を設定：

| 項目 | 推奨値 | 説明 |
|------|--------|------|
| 開始日 | 今日の日付 | 初回実行日 |
| 時刻 | `09:00:00` | 実行開始時刻（業務開始直後等） |
| 間隔 | `1` 日ごと | 毎日実行 |

4. 「**次へ**」をクリック

#### パターン B: 毎週実行（週次レポート転送）

1. 「**毎週**」を選択
2. 設定例：

| 項目 | 設定値 |
|------|--------|
| 開始日 | 今週の月曜日 |
| 時刻 | `08:30:00` |
| 間隔 | `1` 週間ごと |
| 曜日 | ☑ 月 ☑ 火 ☑ 水 ☑ 木 ☑ 金 （土日除外） |

#### パターン C: イベントベース（ファイル到着時）

※ 高度な設定が必要です。「基本タスク」ではなく「タスクの作成」を使用してください。

```xml
<!-- トリガー XML 例（イベントベース） -->
<Triggers>
  <EventTrigger>
    <Enabled>true</Enabled>
    <Subscription>
      &lt;QueryList&gt;
        &lt;Query Id="0" Path="Security"&gt;
          &lt;Select Path="Security"&gt;
            *[System[(EventID=4663)]]
            and *[EventData[Data[@Name='ObjectName'] and Data='C:\Misogi\Inbound']]
          &lt;/Select&gt;
        &lt;/Query&gt;
      &lt;/QueryList&gt;
    </Subscription>
  </EventTrigger>
</Triggers>
```

### Step 4: アクション（実行内容）の設定

> **[スクリーンショット placeholder]**
> 「アクション」選択画面
> 「プログラムの開始」が選択されている状態

1. 「**プログラムの開始**」を選択
2. 「**次へ**」をクリック
3. 以下の情報を入力：

| 項目 | 入力値 | 説明 |
|------|--------|------|
| プログラム/スクリプト | `C:\Misogi\target\release\misogi-sender.exe` | Misogi Sender バイナリへのパス |
| 引数の追加 | `watch --config C:\Misogi\misogi-sender.toml --dir C:\Misogi\Inbound` | watch コマンドの引数 |
| 開始位置 | `C:\Misogi` | 作業ディレクトリ |

**引数の詳細解説**:

```
watch                    ← ファイル監視モード
--config C:\...\toml     ← 設定ファイルパス
--dir C:\Misogi\Inbound  ← 監視対象ディレクトリ（任意）
--convert-jtd-to-pdf     ← JTD ファイルを PDF に変換（必要な場合）
--once                   ← 1 回のみ実行して終了（タスクスケジューラ向け）
```

> **[スクリーンショット placeholder]**
> 「プログラムの開始」詳細設定画面
> 上記の各フィールドに入力済みの状態

4. 「**次へ**」をクリック

### Step 5: Windows の起動時実行（オプション）

「**Windows スタートアップ時**」トリガーを追加することで、
サーバー再起動後も自動的に Misogi が稼働します。

1. トリガー選択画面で「**Windows スタート時に**」を選択
2. 「**次へ**」→ 設定を確認 → 「**完了**」

---

## 3. セキュリティオプションの設定（重要）

### Step 6: ユーザーアカウントの指定

> **[スクリーンショット placeholder]**
> タスクプロパティの「全般」タブ
> 「ユーザーがログインしているかどうかにかかわらず実行する」チェックあり

基本タスク作成完了後、さらにセキュリティ設定を行います：

1. 作成したタスクをダブルクリックしてプロパティを開く
2. 「**全般**」タブで以下を設定：

| 設定項目 | 推奨値 | 理由 |
|---------|--------|------|
| ユーザーがログインしているかどうかにかかわらず実行する | ✅ チェック | サーバー再起動後も自動実行 |
| 最上位の特権で実行する | ✅ チェック | UAC 制限を回避 |
| 非表示にする | □ チェックなし | デバッグ時にコンソール表示 |
| 構成 | **Windows Server 2022** | OS バージョンに合わせる |

### Step 7: アカウントの指定

1. 「**ユーザーまたはグループの変更...**」をクリック
2. 専用サービスアカウントを指定（例: `MisogiService`）
3. パスワードを入力

> **⚠️ 重要**: 必ず専用のサービスアカウントを使用してください。
> Administrator アカウントでの実行はセキュリティ上推奨されません。

---

## 4. 詳細設定（Settings タブ）

### Step 8: 実行設定の調整

「**設定**」タブで以下を確認・設定します：

> **[スクリーンショット placeholder]**
> タスクプロパティの「設定」タブ
> 各チェックボックスの設定状態

| 設定項目 | 推奨値 | 説明 |
|---------|--------|------|
| タスクが失敗した場合の再試行 | ✅ 有効 | 再試行間隔: **1 分**, 試行回数: **3 回** |
| 長時間実行を停止する | ❌ 無効 | CDR 処理は時間がかかる場合があるため |
| アイドル状態の場合は停止 | ❌ 無効 | 同上 |
| 電源が AC で動作中の場合のみ開始 | ✅ 有効 | サーバー環境では常に AC |
| スリープ解除して実行する | ❌ 無効 | サーバーは通常スリープしない |

### Step 9: 条件タブ（Conditions）

| 設定項目 | 推奨値 | 説明 |
|---------|--------|------|
| AC 電源の場合のみ開始 | ✅ | サーバー標準 |
| アイドル状態になってから X 分待つ | ❌ 無効 | 即時実行 |
| ネットワーク接続が利用可能な場合 | ✅ 任意 | 利用可能な接続: **Any connection** |

---

## 5. PowerShell による一括登録（高度な方法）

複数のタスクや多数のサーバーに一括登録する場合は、PowerShell スクリプトを使用できます。

### 5-1: 登録スクリプト例

```powershell
# ============================================================
# Misogi Task Scheduler Registration Script
# Run as Administrator
# ============================================================

$taskName = "Misogi File Watch - Daily"
$misogiExe = "C:\Misogi\target\release\misogi-sender.exe"
$configFile = "C:\Misogi\misogi-sender.toml"
$watchDir = "C:\Misogi\Inbound"
$user = "DOMAIN\MisogiService"
$password = "SecurePassword123!"  # 実際には安全な方法で管理してください

# 既存のタスクを削除（再登録用）
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# アクション定義
$action = New-ScheduledTaskAction `
    -Execute $misogiExe `
    -Argument "watch --config `"$configFile`" --dir `"$watchDir`" --once" `
    -WorkingDirectory "C:\Misogi"

# トリガー定義（毎日 9:00 実行）
$trigger = New-ScheduledTaskTrigger -Daily -At "09:00AM"

# 設定定义
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries:$false `
    -DontStopIfGoingOnBatteries:$false `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2)

# Principal（実行ユーザー）
$principal = New-ScheduledTaskPrincipal `
    -UserId $user `
    -LogonType Password `
    -RunLevel Highest

# タスク登録
Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Password $password `
    -Description "Misogi CDR file watch task (daily)"

Write-Host "タスク '$taskName' を登録しました" -ForegroundColor Green

# 登録確認
Get-ScheduledTask -TaskName $taskName | Format-List TaskName, State, Description
```

### 5-2: 実行結果の確認

```powershell
# タスクの状態確認
Get-ScheduledTask -TaskName "Misogi*" | Format-Table TaskName, State -AutoSize

# 直近の実行履歴
Get-ScheduledTaskInfo -TaskName "Misogi File Watch - Daily" |
    Select-Object LastRunTime, LastTaskResult, NextRunTime
```

**期待される出力**:
```
TaskName                       State
-------                       -----
Misogi File Watch - Daily      Ready

LastRunTime         LastTaskResult NextRunTime
-----------         ------------- ----------
2024/01/15 09:00:03              0 2024/01/16 09:00:00
```

---

## 6. タスク実行結果の確認とトラブルシューティング

### 6-1: 実行履歴の確認

1. タスクスケジューラで該当タスクを選択
2. 「**履歴**」タブをクリック

> **[スクリーンショット placeholder]**
> タスクの履歴タブ
> 各実行の「操作」、「状態」、「コード」が表示されている

### 6-2: 終了コードの意味

| コード | 意味 | 対策 |
|-------|------|------|
| **0** | 正常終了 | 問題なし |
| **0x1** | 不正な関数 / 引数エラー | コマンド引数を確認 |
| **0x2** | ファイルが見つかりません | プログラムパスを確認 |
| **0x3** | 指定されたパスが見つかりません | 設定ファイルパスを確認 |
| **0x41301** | タスクが現在実行中 | 重複実行防止のためスキップ |
| **0x80070005** | Access Denied | 権限不足。サービスアカウント権限を確認 |
| **0x80070002** | ファイル未検出 | 監視ディレクトリや設定ファイルを確認 |

### 6-3: ログの確認

タスク実行時の詳細ログは、以下の場所に出力されます：

```powershell
# イベントビューアーでタスクスケジューラのログを確認
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-TaskScheduler/Operational'
    Id = 102, 103, 129, 201, 202, 203
} -MaxEvents 20 | Format-Table TimeCreated, Id, Message -Wrap
```

---

*関連ドキュメント: [日常運用手順書](daily-operation.md) | [CLI コマンドリファレンス](../api-reference/cli-reference.md)*
