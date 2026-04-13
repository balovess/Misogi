/* =============================================================================
 * Misogi WASM Browser Demo — Application Logic (Main Module)
 * =============================================================================
 * Vanilla ES6 module providing:
 * - Drag-and-drop file upload handling (dragenter, dragover, dragleave, drop)
 * - File type auto-detection via detect_file_type()
 * - Sanitization dispatch (sanitize_pdf / sanitize_office) based on file type
 * - PII scanning via scan_pii() for text-based content
 * - Results rendering: threat count, report, PII table, size comparison
 * - Sanitized file download via Blob + URL.createObjectURL()
 * - Error handling with Japanese user-friendly messages
 * - Memory cleanup (Object URL revocation)
 * - Large file warning (>50MB browser memory limit)
 *
 * ## Module Dependencies
 *
 * - ./feature-detection.js (localizeError)
 * - ./wasm-loader.js (initializeWasm, WASM_LOAD_TIMEOUT_MS)
 *
 * ## WASM Package Path
 *
 * The WASM package is expected at `../pkg/misogi_wasm.js` relative to this file,
 * which corresponds to `crates/misogi-wasm/pkg/` in the project root.
 * Build with: wasm-pack build --target web crates/misogi-wasm
 * ============================================================================= */

// Import feature detection and WASM loader modules
import { localizeError } from "./feature-detection.js";
import { initializeWasm } from "./wasm-loader.js";

// =============================================================================
// Constants
// =============================================================================

/** Maximum recommended file size before showing a warning (50 MB). */
const LARGE_FILE_WARNING_BYTES = 50 * 1024 * 1024;

/** File extensions that trigger PDF sanitization path. */
const PDF_EXTENSIONS = new Set(["pdf"]);

/** File extensions that trigger Office document sanitization path. */
const OFFICE_EXTENSIONS = new Set([
    "docx", "xlsx", "pptx",
    "docm", "xlsm", "pptm",
    "doc", "xls", "ppt",
]);

/** MIME type mapping for sanitized output blobs. */
const MIME_TYPE_MAP = {
    pdf:  "application/pdf",
    docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    doc:  "application/msword",
    xls:  "application/vnd.ms-excel",
    ppt:  "application/vnd.ms-powerpoint",
    docm: "application/vnd.ms-word.document.macroEnabled.12",
    xlsm: "application/vnd.ms-excel.sheet.macroEnabled.12",
    pptm: "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
};

/** Human-readable policy labels in Japanese. */
const POLICY_LABELS = {
    StripActiveContent: "アクティブコンテンツ除去",
    ConvertToFlat:     "フラット変換（最大セキュリティ）",
    TextOnly:           "テキストのみ抽出",
};

/** PII type labels in Japanese for display. */
const PII_TYPE_LABELS = {
    my_number:       "マイナンバー",
    email:           "メールアドレス",
    ip_address_v4:   "IPv4アドレス",
    credit_card:     "クレジットカード番号",
    phone_jp:        "電話番号（日本）",
    postal_code_jp:  "郵便番号（日本）",
    drivers_license: "運転免許証番号",
};

/** PII action labels in Japanese. */
const PII_ACTION_LABELS = {
    block:      "ブロック推奨",
    mask:       "マスキング推奨",
    alert_only: "ログ記録のみ",
};

/** File type icon SVG paths (simplified). */
const FILE_TYPE_ICONS = {
    pdf: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
          stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/>
            <line x1="16" y1="17" x2="8" y2="17"/>
          </svg>`,
    docx: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
           stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2 13"/>
            <line x1="16" y1="17" x2="10" y2="17"/>
          </svg>`,
    xlsx: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
           stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
            <rect x="8" y="12" width="8" height="6" rx="1"/>
          </svg>`,
    pptx: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
           stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
            <circle cx="12" cy="15" r="3"/>
          </svg>`,
    default: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
              stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
          </svg>`,
};

// =============================================================================
// Application State
// =============================================================================

/**
 * Global application state.
 * All mutable state is centralized here for predictability and debugging.
 */
const state = {
    /** Whether the WASM module has been successfully initialized. */
    wasmReady: false,

    /** The currently loaded file object from the input/drop event. */
    currentFile: null,

    /** Raw Uint8Array of the currently loaded file's bytes. */
    fileBytes: null,

    /** File type detection result from detect_file_type(). */
    fileTypeResult: null,

    /** The selected sanitization policy enum value. */
    selectedPolicy: "StripActiveContent",

    /** The most recent sanitization result (SanitizeResult). */
    lastSanitizeResult: null,

    /** The most recent PII scan result (PiiScanResult). */
    lastPiiResult: null,

    /** Blob URL for the sanitized file download (must be revoked after use). */
    downloadUrl: null,
};

// =============================================================================
// DOM Element References (cached after DOMContentLoaded)
// =============================================================================

let dom = {};

/**
 * Cache all DOM element references needed by the application.
 * Called once during initialization to avoid repeated queries.
 */
function cacheDomReferences() {
    dom = {
        // Loading overlay
        wasmLoadingOverlay: document.getElementById("wasm-loading-overlay"),
        wasmLoadingSpinner:  document.getElementById("wasm-loading-spinner"),
        wasmLoadingText:     document.getElementById("wasm-loading-text"),
        wasmLoadingError:    document.getElementById("wasm-loading-error"),

        // Drop zone
        dropZone:      document.getElementById("drop-zone"),
        dropZoneInput: document.getElementById("drop-zone-input"),

        // File info card
        fileInfoCard:            document.getElementById("file-info-card"),
        fileInfoFilename:         document.getElementById("file-info-filename"),
        fileInfoSize:             document.getElementById("file-info-size"),
        fileInfoTypeBadge:        document.getElementById("file-info-type-badge"),
        fileInfoConfidence:       document.getElementById("file-info-confidence"),
        fileInfoFileIcon:         document.getElementById("file-info-file-icon"),
        fileInfoBlockedWarning:   document.getElementById("file-info-blocked-warning"),
        fileInfoLargeFileWarning: document.getElementById("file-info-large-file-warning"),

        // Policy selector
        policySection: document.getElementById("policy-section"),

        // Action bar
        actionBar:        document.getElementById("action-bar"),
        sanitizeBtn:      document.getElementById("sanitize-btn"),
        resetBtn:         document.getElementById("reset-btn"),
        processingStatus: document.getElementById("processing-status"),

        // Results panel
        resultsPanel:         document.getElementById("results-panel"),
        threatCountValue:     document.getElementById("threat-count-value"),
        threatStatusLabel:    document.getElementById("threat-status-label"),
        threatStatusIndicator: document.getElementById("threat-status-indicator"),
        originalSizeValue:    document.getElementById("original-size-value"),
        sanitizedSizeValue:   document.getElementById("sanitized-size-value"),
        sizeDelta:            document.getElementById("size-delta"),
        reportToggle:         document.getElementById("report-toggle"),
        reportContent:        document.getElementById("report-content"),
        reportJson:           document.getElementById("report-json"),
        piiResultsSection:    document.getElementById("pii-results-section"),
        piiTableBody:         document.getElementById("pii-table-body"),
        piiRecommendedAction: document.getElementById("pii-recommended-action"),
        downloadCard:         document.getElementById("download-card"),
        downloadBtn:          document.getElementById("download-btn"),
        downloadFilename:     document.getElementById("download-filename"),
        downloadFilesize:     document.getElementById("download-filesize"),

        // Error banner
        errorBanner:     document.getElementById("error-banner"),
        errorMessage:    document.getElementById("error-message"),
        errorDismissBtn: document.getElementById("error-dismiss-btn"),
    };
}

// =============================================================================
// Drag-and-Drop Handling
// =============================================================================

/**
 * Set up all drag-and-drop event listeners on the drop zone element.
 *
 * Implements the standard HTML5 drag-and-drop API with proper visual feedback:
 * - dragenter / dragover: prevent default to allow drop, show active styling
 * - dragleave: remove active styling (with debounce for nested child events)
 * - drop: read file as ArrayBuffer, convert to Uint8Array, proceed to processing
 */
function setupDragAndDrop() {
    const zone = dom.dropZone;
    if (!zone) return;

    zone.addEventListener("dragenter", (e) => {
        e.preventDefault();
        e.stopPropagation();
        zone.classList.add("drop-zone--active");
    });

    zone.addEventListener("dragover", (e) => {
        e.preventDefault();
        e.stopPropagation();
        zone.classList.add("drop-zone--active");
        e.dataTransfer.dropEffect = "copy";
    });

    let dragLeaveCounter = 0;
    zone.addEventListener("dragenter", () => { dragLeaveCounter++; });
    zone.addEventListener("dragleave", (e) => {
        e.preventDefault();
        e.stopPropagation();
        dragLeaveCounter--;
        if (dragLeaveCounter <= 0) {
            dragLeaveCounter = 0;
            zone.classList.remove("drop-zone--active");
        }
    });

    zone.addEventListener("drop", async (e) => {
        e.preventDefault();
        e.stopPropagation();
        zone.classList.remove("drop-zone--active");
        dragLeaveCounter = 0;

        const files = e.dataTransfer.files;
        if (files && files.length > 0) {
            await handleFileSelection(files[0]);
        }
    });

    if (dom.dropZoneInput) {
        dom.dropZoneInput.addEventListener("change", async (e) => {
            const files = e.target.files;
            if (files && files.length > 0) {
                await handleFileSelection(files[0]);
            }
            e.target.value = "";
        });
    }
}

// =============================================================================
// File Selection & Type Detection
// =============================================================================

/**
 * Process a user-selected file: read bytes, detect type, update UI.
 *
 * @param {File} file - The File object from input[type=file] or drop event.
 */
async function handleFileSelection(file) {
    resetResults();
    hideError();
    state.currentFile = file;

    try {
        const arrayBuffer = await readFileAsArrayBuffer(file);
        state.fileBytes = new Uint8Array(arrayBuffer);
    } catch (err) {
        showError("ファイルの読み込みに失敗しました: " + err.message);
        return;
    }

    await detectFileType();
    showFileInfoCard(file);
    showPolicySection();
    showActionBar();
}

/**
 * Read a File object and return its contents as an ArrayBuffer.
 *
 * @param {File} file - The file to read.
 * @returns {Promise<ArrayBuffer>} The file's raw bytes.
 */
function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(new Error("FileReader error"));
        reader.readAsArrayBuffer(file);
    });
}

/**
 * Call detect_file_type() from the WASM module to identify the file format.
 */
async function detectFileType() {
    if (!state.wasmReady || !state.fileBytes || !state.wasmFunctions?.detect_file_type) {
        state.fileTypeResult = {
            detected_type: "application/octet-stream",
            extension: "",
            confidence: 0,
            is_blocked: false,
            block_reason: null,
        };
        return;
    }

    const headerBytes = state.fileBytes.slice(0, 262);

    try {
        state.fileTypeResult = state.wasmFunctions.detect_file_type(headerBytes);
        console.log("[misogi] File type detected:", state.fileTypeResult);
    } catch (err) {
        console.warn("[misogi] File type detection failed:", err);
        state.fileTypeResult = {
            detected_type: "application/octet-stream",
            extension: "",
            confidence: 0,
            is_blocked: false,
            block_reason: null,
        };
    }
}

// =============================================================================
// UI State Management — File Info Card
// =============================================================================

/**
 * Display the file information card with detected type metadata.
 *
 * @param {File} file - The selected file object.
 */
function showFileInfoCard(file) {
    const card = dom.fileInfoCard;
    if (!card) return;

    const ft = state.fileTypeResult;
    const ext = ft.extension || getExtensionFromFileName(file.name);
    const sizeFormatted = formatFileSize(file.size);

    if (dom.fileInfoFilename) dom.fileInfoFilename.textContent = file.name;
    if (dom.fileInfoSize) dom.fileInfoSize.textContent = sizeFormatted;

    if (dom.fileInfoTypeBadge) {
        const typeName = ft.detected_type !== "application/octet-stream"
            ? ft.detected_type.split("/")[1]?.toUpperCase() || ext.toUpperCase()
            : ext.toUpperCase() || "不明";
        dom.fileInfoTypeBadge.textContent = typeName;
    }

    if (dom.fileInfoConfidence) {
        const pct = Math.round((ft.confidence || 0) * 100);
        dom.fileInfoConfidence.textContent = `信頼度: ${pct}%`;
    }

    if (dom.fileInfoFileIcon) {
        dom.fileInfoFileIcon.innerHTML = FILE_TYPE_ICONS[ext] || FILE_TYPE_ICONS.default;
    }

    if (dom.fileInfoBlockedWarning) {
        if (ft.is_blocked) {
            dom.fileInfoBlockedWarning.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                     stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                </svg>
                ブロックされたファイルタイプ: ${escapeHtml(ft.block_reason || "セキュリティポリシーにより拒否")}
            `;
            dom.fileInfoBlockedWarning.style.display = "inline-flex";
        } else {
            dom.fileInfoBlockedWarning.style.display = "none";
        }
    }

    if (dom.fileInfoLargeFileWarning) {
        if (file.size > LARGE_FILE_WARNING_BYTES) {
            dom.fileInfoLargeFileWarning.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                     stroke="currentColor" stroke-width="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
                ファイルサイズが大きいです (${formatFileSize(file.size)})。
                ブラウザのメモリ制限により処理に時間がかかる場合があります。
            `;
            dom.fileInfoLargeFileWarning.style.display = "inline-flex";
        } else {
            dom.fileInfoLargeFileWarning.style.display = "none";
        }
    }

    card.classList.add("file-info-card--visible");
}

/**
 * Extract file extension from filename (fallback when magic bytes fail).
 *
 * @param {string} fileName - The file name including extension.
 * @returns {string} Lowercase extension without dot, or empty string.
 */
function getExtensionFromFileName(fileName) {
    const dotIndex = fileName.lastIndexOf(".");
    if (dotIndex === -1 || dotIndex === fileName.length - 1) return "";
    return fileName.slice(dotIndex + 1).toLowerCase();
}

// =============================================================================
// UI State Management — Policy & Actions
// =============================================================================

function showPolicySection() {
    if (dom.policySection) dom.policySection.classList.add("policy-section--visible");
}

function showActionBar() {
    if (dom.actionBar) dom.actionBar.classList.add("action-bar--visible");
}

function handlePolicyChange(e) {
    state.selectedPolicy = e.target.value;
    console.log("[misogi] Policy changed to:", state.selectedPolicy);
}

// =============================================================================
// Core Sanitization Logic
// =============================================================================

/**
 * Execute the sanitization pipeline based on detected file type.
 *
 * Dispatches to either sanitize_pdf() or sanitize_office() depending on the
 * detected file extension. Also runs scan_pii() for text-based analysis.
 * Updates the UI with results or displays errors.
 */
async function executeSanitization() {
    if (!state.wasmReady) {
        showError("WASM モジュールがまだ初期化されていません。ページを再読み込みしてください。");
        return;
    }

    if (!state.fileBytes || state.fileBytes.length === 0) {
        showError("ファイルデータがありません。ファイルをドロップまたは選択してください。");
        return;
    }

    if (state.fileTypeResult?.is_blocked) {
        showError(`このファイルタイプはブロックされています: ${state.fileTypeResult.block_reason || "セキュリティポリシー"}`);
        return;
    }

    setProcessingState(true);
    hideError();
    hideResults();

    try {
        const ext = state.fileTypeResult?.extension || getExtensionFromFileName(state.currentFile?.name || "");
        let sanitizeResult;

        if (PDF_EXTENSIONS.has(ext)) {
            console.log(`[misogi] Sanitizing PDF (${formatFileSize(state.fileBytes.length)})...`);
            try {
                sanitizeResult = state.wasmFunctions.sanitize_pdf(
                    Array.from(state.fileBytes),
                    state.selectedPolicy
                );
            } catch (pdfErr) {
                console.error("[misogi] PDF sanitization error:", pdfErr);
                throw new Error(localizeError(pdfErr.message || "PDF サニタイズ中にエラーが発生しました"));
            }
        } else if (OFFICE_EXTENSIONS.has(ext)) {
            console.log(`[misogi] Sanitizing Office document (.${ext}, ${formatFileSize(state.fileBytes.length)})...`);
            try {
                sanitizeResult = state.wasmFunctions.sanitize_office(
                    Array.from(state.fileBytes),
                    state.selectedPolicy
                );
            } catch (officeErr) {
                console.error("[misogi] Office sanitization error:", officeErr);
                throw new Error(localizeError(officeErr.message || "Office ドキュメントのサニタイズ中にエラーが発生しました"));
            }
        } else {
            console.log(`[misogi] File type .${ext} not supported for sanitization. Running PII scan only.`);
            sanitizeResult = null;
        }

        state.lastSanitizeResult = sanitizeResult;

        let piiResult = null;
        try {
            console.log("[misogi] Scanning for PII...");
            piiResult = state.wasmFunctions.scan_pii(Array.from(state.fileBytes));
            state.lastPiiResult = piiResult;
        } catch (piiErr) {
            console.warn("[misogi] PII scan failed (non-fatal):", piiErr);
        }

        renderResults(sanitizeResult, piiResult, ext);

    } catch (err) {
        console.error("[misogi] Sanitization error:", err);
        showError(localizeError(err.message || "サニタイズ処理中に不明なエラーが発生しました"));
    } finally {
        setProcessingState(false);
    }
}

/**
 * Toggle the UI between idle and processing states.
 *
 * @param {boolean} isProcessing - True to show loading state, false for idle.
 */
function setProcessingState(isProcessing) {
    if (!dom.sanitizeBtn || !dom.processingStatus) return;

    dom.sanitizeBtn.disabled = isProcessing;

    if (isProcessing) {
        dom.sanitizeBtn.classList.add("btn--loading");
        dom.processingStatus.style.display = "flex";
        if (dom.dropZone) dom.dropZone.classList.add("drop-zone--disabled");
    } else {
        dom.sanitizeBtn.classList.remove("btn--loading");
        dom.processingStatus.style.display = "none";
        if (dom.dropZone) dom.dropZone.classList.remove("drop-zone--disabled");
    }
}

// =============================================================================
// Results Rendering
// =============================================================================

/**
 * Render the complete results panel with sanitization and PII findings.
 */
function renderResults(sanitizeResult, piiResult, ext) {
    const panel = dom.resultsPanel;
    if (!panel) return;

    renderThreatStatus(sanitizeResult);
    renderSizeComparison(sanitizeResult);
    renderReport(sanitizeResult);
    renderPiiResults(piiResult);
    renderDownloadButton(sanitizeResult, ext);

    panel.classList.add("results-panel--visible");
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

/** Render the threat count status card. */
function renderThreatStatus(result) {
    if (!dom.threatCountValue) return;

    const threatsFound = result?.threats_found ?? 0;
    const isSafe = threatsFound === 0;

    dom.threatCountValue.textContent = threatsFound;
    dom.threatCountValue.className =
        `threat-status__count ${isSafe ? "threat-status__count--safe" : "threat-status__count--threat"}`;

    if (dom.threatStatusLabel) {
        dom.threatStatusLabel.textContent = isSafe ? "件の脅威検出" : "件の脅威を除去";
    }

    if (dom.threatStatusIndicator) {
        dom.threatStatusIndicator.className =
            `threat-status__indicator ${isSafe ? "threat-status__indicator--safe" : "threat-status__indicator--threat"}`;
        dom.threatStatusIndicator.innerHTML = `
            <span class="threat-status__dot"></span>
            ${isSafe ? "クリーン — 脅威は検出されませんでした" : "警告 — 脅威が検出・除去されました"}
        `;
    }
}

/** Render the file size comparison card (original vs sanitized). */
function renderSizeComparison(result) {
    if (!dom.originalSizeValue || !state.fileBytes) return;

    const originalSize = state.fileBytes.length;
    const sanitizedSize = result?.output_data?.length ?? originalSize;
    const delta = sanitizedSize - originalSize;
    const deltaPercent = originalSize > 0 ? ((delta / originalSize) * 100).toFixed(1) : 0;

    dom.originalSizeValue.textContent = formatFileSize(originalSize);
    dom.sanitizedSizeValue.textContent = formatFileSize(sanitizedSize);

    if (dom.sizeDelta) {
        if (delta < 0) {
            dom.sizeDelta.textContent = `${formatFileSize(Math.abs(delta))} 減少 (-${deltaPercent}%)`;
            dom.sizeDelta.className = "size-comparison__delta size-comparison__delta--reduced";
        } else if (delta > 0) {
            dom.sizeDelta.textContent = `${formatFileSize(delta)} 増加 (+${deltaPercent}%)`;
            dom.sizeDelta.className = "size-comparison__delta size-comparison__delta--increased";
        } else {
            dom.sizeDelta.textContent = "変更なし";
            dom.sizeDelta.className = "size-comparison__delta size-comparison__delta--same";
        }
    }
}

/** Render the expandable/collapsible sanitization report card. */
function renderReport(result) {
    if (!dom.reportJson) return;

    if (result?.report) {
        try {
            const parsed = JSON.parse(result.report);
            dom.reportJson.textContent = JSON.stringify(parsed, null, 2);
        } catch {
            dom.reportJson.textContent = result.report;
        }
        if (dom.reportToggle?.closest(".result-card")) {
            dom.reportToggle.closest(".result-card").style.display = "";
        }
    } else {
        if (dom.reportToggle?.closest(".result-card")) {
            dom.reportToggle.closest(".result-card").style.display = "none";
        }
    }
}

/** Render PII scan results as a table with match details. */
function renderPiiResults(result) {
    const section = dom.piiResultsSection;
    if (!section) return;

    if (!result || !result.found || result.matches.length === 0) {
        section.style.display = "none";
        return;
    }

    section.style.display = "";

    if (dom.piiRecommendedAction) {
        const actionKey = result.recommended_action || "alert_only";
        const actionLabel = PII_ACTION_LABELS[actionKey] || actionKey;
        const actionClass = actionKey === "block" ? "pii-action-badge--block"
            : actionKey === "mask" ? "pii-action-badge--mask"
            : "pii-action-badge--alert";
        dom.piiRecommendedAction.innerHTML =
            `<span class="pii-action-badge ${actionClass}">推奨アクション: ${actionLabel}</span>`;
    }

    if (dom.piiTableBody) {
        dom.piiTableBody.innerHTML = result.matches.map((match) => {
            const typeLabel = PII_TYPE_LABELS[match.pii_type] || match.pii_type;
            const contextEscaped = escapeHtml(match.context || "");
            return `
                <tr>
                    <td><span class="pii-table__type-badge">${escapeHtml(typeLabel)}</span></td>
                    <td><span class="pii-table__offset">${match.offset}</span></td>
                    <td><span class="pii-table__context" title="${contextEscaped}">${contextEscaped}</span></td>
                </tr>
            `;
        }).join("");
    }
}

/** Render the download button for the sanitized file. */
function renderDownloadButton(result, ext) {
    const card = dom.downloadCard;
    if (!card) return;

    if (!result?.output_data || result.output_data.length === 0) {
        card.style.display = "none";
        return;
    }

    card.style.display = "";
    revokeDownloadUrl();

    const outputBytes = new Uint8Array(result.output_data);
    const mimeType = MIME_TYPE_MAP[ext] || "application/octet-stream";
    const blob = new Blob([outputBytes], { type: mimeType });
    state.downloadUrl = URL.createObjectURL(blob);

    const originalName = state.currentFile?.name || "sanitized_file";
    const sanitizedName = generateSanitizedFilename(originalName);

    if (dom.downloadBtn) {
        dom.downloadBtn.href = state.downloadUrl;
        dom.downloadBtn.download = sanitizedName;
    }

    if (dom.downloadFilename) dom.downloadFilename.textContent = sanitizedName;
    if (dom.downloadFilesize) dom.downloadFilesize.textContent = formatFileSize(outputBytes.length);
}

/** Generate a sanitized filename by inserting "_sanitized" before the extension. */
function generateSanitizedFilename(originalName) {
    const dotIndex = originalName.lastIndexOf(".");
    if (dotIndex <= 0) return `${originalName}_sanitized`;
    return `${originalName.slice(0, dotIndex)}_sanitized${originalName.slice(dotIndex)}`;
}

/** Revoke the current download blob URL to free browser memory. */
function revokeDownloadUrl() {
    if (state.downloadUrl) {
        URL.revokeObjectURL(state.downloadUrl);
        state.downloadUrl = null;
    }
}

// =============================================================================
// Report Toggle (Expand/Collapse)
// =============================================================================

function toggleReport() {
    if (!dom.reportToggle || !dom.reportContent) return;
    const isExpanded = dom.reportContent.classList.toggle("report-card__content--expanded");
    dom.reportToggle.setAttribute("aria-expanded", String(isExpanded));
}

// =============================================================================
// Error Handling & Display
// =============================================================================

function showError(message) {
    if (!dom.errorBanner || !dom.errorMessage) return;
    dom.errorMessage.textContent = message;
    dom.errorBanner.classList.add("error-banner--visible");
    dom.errorBanner.style.display = "";
}

function hideError() {
    if (!dom.errorBanner) return;
    dom.errorBanner.classList.remove("error-banner--visible");
    setTimeout(() => {
        if (dom.errorBanner && !dom.errorBanner.classList.contains("error-banner--visible")) {
            dom.errorBanner.style.display = "none";
        }
    }, 400);
}

function dismissError() {
    hideError();
}

// =============================================================================
// Reset Functionality
// =============================================================================

function resetAll() {
    revokeDownloadUrl();
    state.currentFile = null;
    state.fileBytes = null;
    state.fileTypeResult = null;
    state.lastSanitizeResult = null;
    state.lastPiiResult = null;

    hideFileInfoCard();
    hidePolicySection();
    hideActionBar();
    hideResults();
    hideError();

    window.scrollTo({ top: 0, behavior: "smooth" });
    console.log("[misogi] Application state reset.");
}

function hideFileInfoCard() {
    if (dom.fileInfoCard) dom.fileInfoCard.classList.remove("file-info-card--visible");
}
function hidePolicySection() {
    if (dom.policySection) dom.policySection.classList.remove("policy-section--visible");
}
function hideActionBar() {
    if (dom.actionBar) dom.actionBar.classList.remove("action-bar--visible");
}
function hideResults() {
    if (dom.resultsPanel) dom.resultsPanel.classList.remove("results-panel--visible");
    if (dom.reportContent) dom.reportContent.classList.remove("report-card__content--expanded");
    if (dom.reportToggle) dom.reportToggle.setAttribute("aria-expanded", "false");
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Format a byte count into a human-readable file size string.
 * Uses binary prefixes (KiB, MiB, GiB) for accuracy.
 *
 * @param {number} bytes - Byte count.
 * @returns {string} Formatted size string (e.g., "1.5 MB").
 */
function formatFileSize(bytes) {
    if (bytes === 0) return "0 B";

    const units = ["B", "KB", "MB", "GB"];
    const k = 1024;
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    const size = bytes / Math.pow(k, i);

    const formatted = size >= 10 ? Math.round(size) : size.toFixed(1);
    return `${formatted} ${units[i]}`;
}

/**
 * Escape HTML special characters to prevent XSS when inserting user-provided
 * strings into innerHTML.
 *
 * @param {string} str - Raw string potentially containing HTML characters.
 * @returns {string} Escaped string safe for innerHTML insertion.
 */
function escapeHtml(str) {
    const div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

// =============================================================================
// Event Binding & Application Bootstrap
// =============================================================================

/**
 * Bind all event listeners once the DOM is fully loaded.
 *
 * This function serves as the main entry point for the application logic layer.
 * It caches DOM references, sets up interactions, and kicks off WASM init.
 *
 * ## Progressive Loading Strategy
 *
 * The UI is shown immediately (not blocked by WASM loading) to provide fast
 * perceived performance. Interactive features are enabled only after WASM
 * initialization completes successfully.
 */
function bootstrapApp() {
    cacheDomReferences();
    setupDragAndDrop();

    // Sanitize button click handler (enabled after WASM ready)
    if (dom.sanitizeBtn) {
        dom.sanitizeBtn.disabled = true;
        dom.sanitizeBtn.setAttribute("aria-busy", "true");
        dom.sanitizeBtn.addEventListener("click", executeSanitization);
    }

    // Reset button click handler (always available)
    if (dom.resetBtn) dom.resetBtn.addEventListener("click", resetAll);

    // Policy radio change handlers
    document.querySelectorAll('input[name="policy"]').forEach((radio) => {
        radio.addEventListener("change", handlePolicyChange);
    });

    // Report expand/collapse toggle
    if (dom.reportToggle) dom.reportToggle.addEventListener("click", toggleReport);

    // Error dismiss handler
    if (dom.errorDismissBtn) dom.errorDismissBtn.addEventListener("click", dismissError);

    // Keyboard accessibility for drop zone
    if (dom.dropZone) {
        dom.dropZone.setAttribute("tabindex", "0");
        dom.dropZone.setAttribute("role", "button");
        dom.dropZone.setAttribute("aria-label", "ファイルをドロップまたはクリックして選択");

        dom.dropZone.addEventListener("keydown", (e) => {
            if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                dom.dropZoneInput?.click();
            }
        });
    }

    // Initialize WASM module asynchronously (non-blocking UI display)
    initializeWasm(dom, state);

    console.log("[misogi] Application bootstrapped. Waiting for WASM initialization...");
}

// =============================================================================
// Entry Point — Wait for DOM ready, then bootstrap
// =============================================================================

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrapApp);
} else {
    bootstrapApp();
}
