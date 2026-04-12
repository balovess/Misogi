# ⚛️ React Frontend (gRPC-Web)

## React + TypeScript によるブラウザベースの Misogi 操作 UI

本プロジェクトは、ブラウザ環境から直接 Misogi CDR エンジンを操作するための
React 18 フロントエンドアプリケーションの完全な実装例です。

gRPC-Web プロトコル + Envoy プロキシ経由で、ネイティブに近いパフォーマンスで
gRPC サービスにアクセスします。

---

## 📋 Overview / 概要

| Item | Detail |
|------|--------|
| **Framework** | React 18.3+ / TypeScript 5.6+ |
| **Build Tool** | Vite 5.4+ |
| **gRPC Transport** | @improbable-eng/grpc-web (browser-compatible) |
| **Styling** | CSS Custom Properties (no external framework) |
| **Protocol** | `misogi.file_transfer.v1` via gRPC-Web → Envoy → Tonic |

### Architecture / アーキテクチャ

```
Browser (React App)
    │
    │ gRPC-Web (HTTP/1.1 or HTTP/2 framing)
    ▼
Envoy Proxy (:8080) - gRPC-Web ↔ gRPC translation
    │
    │ native gRPC (HTTP/2)
    ▼
Misogi Tonic Server (:50051)
```

### Target Use Cases / 対象ユースケース

- オペレーター向けファイル送受信ダッシュボード
- 管理者向け CDR ポリシー設定 UI
- ファイルステータスのリアルタイムモニタリング
- SIer 現場でのポータルサイト構築
- セキュリティチーム向け脅威レポート閲覧

---

## 🔧 Prerequisites / 前提条件

```bash
# Required
node --version   # >= 18.x LTS
npm --version    # >= 9.x

# For local development
docker --version # Optional: for running Envoy via Docker
```

### Backend Requirements / バックエンド要件

- **Misogi Server**: Running on `localhost:50051`
- **Envoy Proxy**: Configured and running on `localhost:8080`
  - Configuration file: `public/envoy.yaml`

---

## 🚀 Quick Start / クイックスタート

### Step 1: Install Dependencies / 依存関係のインストール

```bash
cd examples/web-react
npm install
```

This installs:
- React 18 + ReactDOM
- TypeScript 5.6
- Vite 5.4 (build tool)
- @improbable-eng/grpc-web (gRPC-Web client)
- google-protobuf (message types)

### Step 2: Start Envoy Proxy / Envoyプロキシの起動

**Option A: Using Docker (Recommended)**

```bash
# Build and run Envoy with provided config
docker run -d \
  --name misogi-envoy \
  -p 8080:8080 \
  -p 9901:9901 \
  -v $(pwd)/public/envoy.yaml:/etc/envoy/envoy.yaml \
  envoyproxy/envoy:v1.29-latest -c /etc/envoy/envoy.yaml
```

**Option B: Native Installation**

```bash
# Install Envoy (see https://www.envoyproxy.io/docs/envoy/latest/start/install)
envoy -c public/envoy.yaml
```

Verify Envoy is running:

```bash
curl http://localhost:9901/server_info
```

### Step 3: Start Misogi Server / Misogiサーバーの起動

Ensure your Misogi Tonic server is running on port 50051.

```bash
# From project root
cargo run --release --bin misogi-server
```

### Step 4: Start Development Server / 開発サーバーの起動

```bash
npm run dev
```

The application will be available at:
- **Local**: http://localhost:3000
- **Network**: http://[your-ip]:3000

The dev server automatically proxies gRPC-Web requests to Envoy on port 8080.

---

## 📁 Project Structure / プロジェクト構成

```
web-react/
├── index.html                    # Entry HTML (Japanese lang attribute)
├── package.json                  # Dependencies & scripts
├── tsconfig.json                 # TypeScript config (strict mode)
├── tsconfig.node.json            # Node.js TypeScript config
├── vite.config.ts                # Vite build configuration
├── env.d.ts                      # Vite type declarations
│
├── public/
│   └── envoy.yaml               # Envoy gRPC-Web proxy config
│
└── src/
    ├── main.tsx                 # Application entry point
    ├── App.tsx                  # Root component (layout + routing)
    ├── index.css                # Global styles & design system
    │
    ├── types/
    │   └── proto.ts             # Proto message type definitions
    │
    ├── client/
    │   └── grpc.ts              # gRPC-Web client module
    │
    ├── hooks/
    │   └── useMisogiClient.ts   # React hooks for client lifecycle
    │
    └── components/
        ├── Header.tsx           # App header (branding, status, i18n)
        ├── FileUploader.tsx     # Main upload/sanitize UI
        └── SanitizationReport.tsx # Threat analysis report viewer
```

---

## 🔗 Component Documentation / コンポーネント解説

### Header (`src/components/Header.tsx`)

Application header displaying:
- **Branding**: Misogi logo (禊) + subtitle
- **Connection Status**: Real-time indicator showing backend connectivity
- **Language Toggle**: JA/EN switch (stub for future i18n)

**Props**:
```typescript
interface HeaderProps {
  connection: ConnectionState;      // Current connection state
  onRetryConnection?: () => void;  // Retry callback when disconnected
  locale?: string;                 // Current language ('ja' | 'en')
  onLocaleChange?: (locale: string) => void;  // Locale change handler
}
```

### FileUploader (`src/components/FileUploader.tsx`)

Core interaction component providing complete sanitization workflow:

**Features**:
- Drag-and-drop zone with visual feedback animations
- File selection button (fallback for non-drag environments)
- Selected file information display (name, size, type icon)
- Sanitization policy selector dropdown:
  - アクティブコンテンツ除去 (Strip Active Content)
  - フラット変換 (Convert to Flat)
  - テキストのみ抽出 (Text Only)
  - 最大セキュリティ (Maximum Security)
- Upload progress bar with percentage display
- Status panel showing current processing phase
- Error display with retry option
- Download button for sanitized files
- All labels in Japanese (i18n-ready constants)

**Lifecycle Phases**:
```
IDLE → SELECTED → UPLOADING → PROCESSING → READY → DOWNLOADING → COMPLETED
                                    ↓
                                  ERROR (with retry)
```

**Props**:
```typescript
interface FileUploaderProps {
  client: MisogigRpcClient;  // Initialized gRPC-Web client
}
```

### SanitizationReport (`src/components/SanitizationReport.tsx`)

Collapsible threat analysis viewer displaying:

**Sections**:
1. **Summary Card**: Aggregated statistics by severity level
   - Total findings count
   - Critical/High/Medium/Low/Info breakdowns
2. **Detailed Table**: Individual threat findings list
   - Severity badge (color-coded)
   - Category classification
   - Description of threat
   - Location in file (if applicable)
   - Action taken by sanitizer
3. **PII Detection**: Personally Identifiable Information status
4. **Policy Info**: Applied sanitization policy name
5. **Processing Metadata**: Timestamp, duration, file identifiers

**Props**:
```typescript
interface SanitizationReportProps {
  report: SanitizationReportType;  // Complete analysis results
}
```

---

## 🪝 Custom Hooks / カスタムフック

### useMisogiClient()

Initializes and manages gRPC-Web client instance.

**Returns**:
```typescript
{
  connection: ConnectionState;      // UNKNOWN | TESTING | CONNECTED | DISCONNECTED
  client: MisogigRpcClient | null;  // Client instance (null until connected)
  error: string | null;            // Connection error message
  retryConnection: () => void;     // Manual retry function
}
```

**Usage**:
```tsx
function App() {
  const { client, connection } = useMisogiClient('http://localhost:8080');

  return (
    <Header connection={connection} />
    {client && <FileUploader client={client} />}
  );
}
```

### useSanitize(client)

Manages complete upload → status poll → download lifecycle.

**Returns**:
```typescript
{
  // State
  phase: SanitizePhase;
  file: File | null;
  policy: SanitizationPolicyType;
  uploadProgress: number;         // 0-100
  uploadResponse: UploadResponse | null;
  fileStatus: FileStatusResponse | null;
  resultBlob: Blob | null;
  report: SanitizationReport | null;
  error: string | null;

  // Actions
  selectFile: (file: File) => void;
  setPolicy: (policy: SanitizationPolicyType) => void;
  startSanitize: () => Promise<void>;
  downloadResult: (filename?: string) => Promise<void>;
  reset: () => void;
}
```

**Usage**:
```tsx
function SanitizePanel({ client }: { client: MisogigRpcClient }) {
  const { phase, selectFile, startSanitize, downloadResult, progress } = useSanitize(client);

  return (
    <>
      <FileInput onSelect={selectFile} disabled={phase !== 'IDLE'} />
      <Button onClick={startSanitize} disabled={phase !== 'SELECTED'}>
        浄化開始
      </Button>
      <ProgressBar value={progress} visible={phase === 'UPLOADING'} />
      <Button onClick={downloadResult} disabled={phase !== 'READY'}>
        ダウンロード
      </Button>
    </>
  );
}
```

---

## 🌐 gRPC-Web Client API / クライアントAPI

### MisogigRpcClient Class

Full-featured gRPC-Web client for all Misogi service operations.

**Constructor**:
```typescript
const client = new MisogigRpcClient('http://localhost:8080');
// Default host: http://localhost:8080
```

**Methods**:

#### `uploadFile(file, policy, onProgress?)`

Stream file to server with chunked transfer and progress tracking.

```typescript
const response = await client.uploadFile(
  file,
  SanitizationPolicy.STRIP_ACTIVE_CONTENT,
  (sent, total) => console.log(`${(sent/total*100).toFixed(1)}%`)
);
// Returns: { file_id: string, status: UploadStatus }
```

#### `getFileStatus(fileId)`

Query current state of uploaded file.

```typescript
const status = await client.getFileStatus('abc-123');
// Returns: FileStatusResponse with chunk_count, completed_chunks, etc.
```

#### `listFiles(params?)`

List files on sender node with pagination.

```typescript
const result = await client.listFiles({ page: 0, per_page: 20 });
// Returns: { files: FileStatusResponse[], total: number }
```

#### `triggerTransfer(fileId)`

Initiate file transfer from sender to receiver.

```typescript
const result = await client.triggerTransfer('abc-123');
// Returns: TransferResponse with status and message
```

#### `downloadFile(fileId, onChunk?)`

Download sanitized file with streaming chunks.

```typescript
const blob = await client.downloadFile('abc-123', (data, offset, total) => {
  console.log(`Received ${data.byteLength} bytes`);
});
// Returns: Blob object ready for browser download
```

#### `testConnection()`

Verify connectivity to Misogi backend through Envoy.

```typescript
const isConnected = await client.testConnection();
// Returns: boolean
```

### Singleton Access

For applications with single backend connection:

```typescript
import { getMisogiClient } from './client/grpc';

const client = getMisogiClient();  // Creates if not exists
const sameClient = getMisogiClient();  // Returns cached instance
```

---

## 🎨 Design System / デザインシステム

### Color Palette / カラーパレット

| Token | Value | Usage |
|-------|-------|-------|
| `--color-primary` | `#2563eb` | Primary actions, links |
| `--color-success` | `#22c55e` | Success states, downloads |
| `--color-warning` | `#f59e0b` | Warnings, PII detected |
| `--color-error` | `#ef4444` | Errors, critical threats |
| `--color-bg-dark` | `#1e293b` | Header background |
| `--color-bg-light` | `#f8fafc` | Page background |

### Typography / タイポグラフィ

**Japanese Font Stack**:
```css
font-family: 'Hiragino Kaku Gothic ProN',
             'Hiragino Sans',
             'Meiryo',
             'Yu Gothic',
             system-ui, sans-serif;
```

**Scale**: 12px (xs) → 30px (3xl) using 4px-based spacing system.

### Responsive Breakpoints / レスポンシブブレークポイント

- **Desktop**: > 768px (default layout)
- **Tablet**: ≤ 768px (stacked layout, full-width buttons)
- **Mobile**: ≤ 480px (condensed spacing, smaller fonts)

### Accessibility / アクセシビリティ

- WCAG 2.1 AA compliant color contrast ratios
- Keyboard navigation support (Tab, Enter, Space)
- ARIA labels and roles throughout
- Focus-visible outlines
- Reduced motion support (`prefers-reduced-motion`)
- High contrast mode compatibility (`forced-colors`)

---

## 🔨 Available Scripts / 利用可能なスクリプト

### Development / 開発

```bash
npm run dev          # Start Vite dev server (port 3000)
npm run preview      # Preview production build locally
```

### Build / ビルド

```bash
npm run build        # Type-check + production bundle
```

Output: `dist/` directory with optimized assets.

### Code Generation / コード生成

```bash
npm run generate:proto
```

Generates TypeScript types from proto definition using protoc + grpc-web plugin.
**Note**: Requires `protoc` installed in PATH.

Generated output goes to `src/generated/`.

---

## 🚢 Production Deployment / 本番デプロイ

### Environment Configuration / 環境設定

Update the following for production:

1. **Envoy Host**: Change in `vite.config.ts` proxy config
2. **Backend URL**: Pass as environment variable or config
3. **CORS Headers**: Configure Envoy for your domain

Example production configuration:

```typescript
// vite.config.ts
export default defineConfig({
  server: {
    proxy: {
      '/misogi.file_transfer.v1': {
        target: process.env.ENVOY_URL ?? 'http://envoy.internal:8080',
        changeOrigin: true,
      },
    },
  },
});
```

### Build Optimization / ビルド最適化

The production build includes:
- Tree-shaking unused code
- Minification (Terser)
- CSS optimization
- Source maps for debugging
- Asset hashing for cache busting

### Docker Deployment / デプロイ (Docker)

Create a `Dockerfile` for containerized deployment:

```dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

---

## 🧪 Testing Strategy / テスト戦略

### Recommended Test Structure / 推奨テスト構成

```
src/
├── __tests__/
│   ├── components/
│   │   ├── FileUploader.test.tsx
│   │   ├── SanitizationReport.test.tsx
│   │   └── Header.test.tsx
│   ├── hooks/
│   │   └── useMisogiClient.test.ts
│   └── client/
│       └── grpc.test.ts
├── mocks/
│   └── grpc-web.mock.ts
```

### Test Framework Recommendations / テストフレームワーク推奨

- **Unit Tests**: Vitest + React Testing Library
- **E2E Tests**: Playwright or Cypress
- **Component Tests**: Storybook for visual regression

### Mocking gRPC-Web / gRPC-Webのモック

Use MSW (Mock Service Worker) or jest.mock for testing without backend:

```typescript
// __mocks__/grpc-web.ts
export class GrpcWebClientBase {
  rpcCall = jest.fn().mockResolvedValue({
    message: { file_id: 'test-id', status: 'READY' }
  });
}
```

---

## 🔒 Security Considerations / セキュリティ考慮事項

### Input Validation / 入力検証

- File type validation on client side (supplement server-side checks)
- Maximum file size limits (configurable via Envoy: 512MB default)
- Filename sanitization before display

### Data Protection / データ保護

- No sensitive data stored in localStorage/sessionStorage
- File content only transmitted via encrypted HTTPS in production
- PII detection results displayed but not persisted locally

### CORS Policy / CORSポリシー

Envoy handles cross-origin requests. Configure allowed origins in `envoy.yaml`:

```yaml
cors:
  allowed_origins:
    - "https://your-domain.com"
  allowed_methods: ["POST", "GET", "OPTIONS"]
```

---

## 📚 Related Links / 関連リンク

### Internal / 内部リソース

- [Proto Definition](../../proto-dist/v1/misogi.proto) — gRPC サービス定義 (V1 stable API)
- [Misogi Core](../../crates/misogi-core/) — Rust コアエンジン実装
- [Parent Index](../README.md) — 全サンプル一覧

### External Dependencies / 外部依存

- [React 18](https://react.dev/) — UI library
- [Vite 5](https://vitejs.dev/) — Build tool
- [grpc-web](https://github.com/grpc/grpc-web) — Browser gRPC transport
- [Envoy Proxy](https://www.envoyproxy.io/) — gRPC-Web translation layer

### Documentation / ドキュメント

- [gRPC-Web Guide](https://grpc.io/docs/languages/web/basics/)
- [Envoy gRPC-Web Filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/grpc_web_filter)
- [Tonic (Rust gRPC)]https://docs.rs/tonic/latest/tonic/

---

## 📄 License / ライセンス

See [LICENSE](../../LICENSE) in repository root.

---

## 🤝 Contributing / 貢献

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Code Style / コードスタイル

- TypeScript strict mode enabled
- ESLint + Prettier recommended
- Japanese comments with JSDoc documentation
- Functional components only (no class components)
- CSS Modules or inline styles (no external framework dependency)

---

## ❓ FAQ / よくある質問

### Q: Why gRPC-Web instead of REST? / Q: なぜRESTではなくgRPC-Web？

A: gRPC provides:
- **Type safety**: Compile-time proto validation
- **Performance**: Binary protocol smaller than JSON
- **Streaming**: Real-time bidirectional communication
- **Code generation**: Auto-generated TS types from proto

Trade-off: Requires Envoy proxy for browser compatibility.

### Q: Can I use this without Envoy? / Q: Envoyなしで使用可能？

A: Not directly in browsers. Alternatives:
- **connect-web** (Connect RPC): Works over HTTP/1.1 without Envoy
- **REST gateway**: Add REST adapter to Misogi server
- **Node.js/Electron**: Use native gRPC directly

### Q: How do I add authentication? / Q: 認証はどう追加？

A: Options:
- **JWT tokens**: Pass in gRPC metadata headers
- **mTLS**: Configure Envoy for mutual TLS
- **OAuth2**: Integrate with identity provider

Example:
```typescript
const client = new MisogigRpcClient(host);
// Metadata will be added to each request
```

### Q: Large file uploads timeout? / Q: 大きなファイルのアップロードがタイムアウト？

A: Configure timeouts in multiple places:
1. **Envoy**: `max_stream_duration` in listener config
2. **Vite dev server**: Increase proxy timeout
3. **Browser**: Handle long-running operations gracefully

Current defaults support up to 512MB files.

---

**Last Updated**: 2026-04-11
**Version**: 0.1.0 (Initial Release)
**Status**: ✅ Production Ready (Reference Implementation)
