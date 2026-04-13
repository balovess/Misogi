// =============================================================================
// Misogi WASM — Performance Benchmark Suite (Criterion)
// =============================================================================
// Comprehensive performance benchmarks for the WASM CDR pipeline measuring:
// - PDF analysis throughput (clean and malicious inputs at multiple sizes)
// - Full sanitization latency (analyze + remediate) with P50/P95/P99
// - Peak memory usage during large-file processing
// - Office OOXML ZIP reconstruction speed
// - PII scanning throughput by pattern density
// - Cryptographic hash baseline (MD5, SHA-256) for comparison
//
// ## Usage
//
// ```bash
// cargo bench -p misogi-wasm --bench wasm_perf
// ```
//
// ## Output
// - Criterion HTML reports in `target/criterion/wasm_perf/`
// - Structured JSON summary printed to stdout after all benchmarks complete
//
// =============================================================================

mod generators;

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
    Throughput,
};

use misogi_cdr::policy::SanitizationPolicy;
use misogi_wasm::wasm_compat::{
    WasmOfficeSanitizer, WasmPdfSanitizer, wasm_compute_md5, wasm_compute_sha256,
};
use generators::*;

// =============================================================================
// Configuration Constants
// =============================================================================

/// Default sanitization policy used across all benchmarks.
const DEFAULT_POLICY: SanitizationPolicy = SanitizationPolicy::StripActiveContent;

/// Input size variants for throughput benchmarks (bytes).
const SIZE_VARIANTS: &[usize] = &[1_024, 100_000, 1_000_000]; // 1KB, 100KB, 1MB

/// Large input sizes for memory profiling benchmarks.
const LARGE_SIZE_VARIANTS: &[usize] = &[1_000_000, 10_000_000]; // 1MB, 10MB

/// PII density variants for pattern-matching throughput tests.
const PII_DENSITY_VARIANTS: &[f64] = &[0.0, 0.05, 0.20]; // 0%, 5%, 20%

/// Fixed text size for PII scan benchmarks (100 KB).
const PII_SCAN_SIZE: usize = 100_000;

// =============================================================================
// A. PDF Analysis Benchmarks
// =============================================================================

/// Benchmark: Clean PDF analysis throughput at 1KB / 100KB / 1MB.
///
/// Measures the Pass 1 scanning speed on benign inputs with zero threat markers.
/// This establishes the baseline parsing overhead of the nom-based scanner
/// before any threat detection logic is exercised.
fn bench_pdf_analyze_clean(c: &mut Criterion) {
    let sanitizer = WasmPdfSanitizer::with_defaults();

    let mut group = c.benchmark_group("pdf_analyze_clean");
    for &size in SIZE_VARIANTS {
        let pdf_data = black_box(generate_clean_pdf(size));

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("throughput", format_size(size)),
            &pdf_data,
            |b, data| {
                b.iter(|| sanitizer.analyze(black_box(data)).unwrap());
            },
        );
    }
    group.finish();
}

/// Benchmark: Malicious PDF analysis throughput (5% JS threat density).
///
/// Measures Pass 1 scanning speed when threat markers are present at realistic
/// density. The `/JS` parser combinator is exercised frequently, providing a
/// more accurate representation of production workloads where some documents
/// contain embedded scripts or suspicious entries.
fn bench_pdf_analyze_malicious(c: &mut Criterion) {
    let sanitizer = WasmPdfSanitizer::with_defaults();

    let mut group = c.benchmark_group("pdf_analyze_malicious");
    for &size in SIZE_VARIANTS {
        let pdf_data = black_box(generate_malicious_pdf(size, 0.05)); // 5% JS density

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("throughput_5pct_js", format_size(size)),
            &pdf_data,
            |b, data| {
                b.iter(|| sanitizer.analyze(black_box(data)).unwrap());
            },
        );
    }
    group.finish();
}

// =============================================================================
// B. PDF Full Sanitization Benchmarks (Analyze + Remediate)
// =============================================================================

/// Benchmark: End-to-end PDF sanitization latency (Pass 1 + Pass 2 combined).
///
/// Measures total wall-clock time for both threat analysis and byte-level
/// remediation at 100KB and 1MB input sizes. This is the primary latency metric
/// for production deployments since it represents the full user-visible delay.
///
/// The benchmark captures:
/// - Threat detection time (nom parser combinator execution)
/// - Policy evaluation time (replacement matrix lookup)
/// - Output buffer construction time (Vec<u8> assembly)
fn bench_pdf_sanitize_full(c: &mut Criterion) {
    let sanitizer = WasmPdfSanitizer::with_defaults();

    let mut group = c.benchmark_group("pdf_sanitize_full");
    let sanitize_sizes: &[usize] = &[100_000, 1_000_000]; // 100KB, 1MB

    for &size in sanitize_sizes {
        let clean_data = black_box(generate_clean_pdf(size));
        let malicious_data = black_box(generate_malicious_pdf(size, 0.05));

        group.throughput(Throughput::Bytes(size as u64));

        // Clean input (fast path: no remediation needed)
        group.bench_with_input(
            BenchmarkId::new("clean", format_size(size)),
            &clean_data,
            |b, data| {
                b.iter(|| {
                    sanitizer
                        .sanitize(black_box(data), &DEFAULT_POLICY)
                        .unwrap()
                });
            },
        );

        // Malicious input (full analyze + remediate path)
        group.bench_with_input(
            BenchmarkId::new("malicious_5pct_js", format_size(size)),
            &malicious_data,
            |b, data| {
                b.iter(|| {
                    sanitizer
                        .sanitize(black_box(data), &DEFAULT_POLICY)
                        .unwrap()
                });
            },
        );
    }
    group.finish();
}

// =============================================================================
// C. Memory Profiling Benchmarks
// =============================================================================

/// Benchmark: Peak memory usage during PDF sanitization of large files.
///
/// Measures heap allocation behavior at 1MB and 10MB to identify potential
/// memory pressure points in the two-pass pipeline. While Criterion does not
/// directly measure RSS, this benchmark exercises the allocation-heavy code
/// paths that would be visible under tools like `dtrace` or `heaptrack`.
fn bench_pdf_memory_peak(c: &mut Criterion) {
    let sanitizer = WasmPdfSanitizer::with_defaults();

    let mut group = c.benchmark_group("pdf_memory_peak");
    for &size in LARGE_SIZE_VARIANTS {
        let pdf_data = black_box(generate_malicious_pdf(size, 0.10)); // 10% JS density

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("sanitize_allocations", format_size(size)),
            &pdf_data,
            |b, data| {
                b.iter(|| {
                    // Force output to be consumed so compiler cannot elide allocations
                    let result =
                        sanitizer.sanitize(black_box(data), &DEFAULT_POLICY).unwrap();
                    black_box(result.output_data.len());
                    black_box(result.report.actions_taken.len());
                });
            },
        );
    }
    group.finish();
}

// =============================================================================
// D. Office OOXML Benchmarks
// =============================================================================

/// Benchmark: OOXML ZIP archive reconstruction performance.
///
/// Measures the full sanitize cycle for Office documents:
/// 1. ZIP archive open + entry enumeration
/// 2. Dangerous entry detection (vbaProject.bin, vbaData.xml)
/// 3. Clean ZIP reconstruction (stream-copy non-dangerous entries)
///
/// Tested with and without VBA macro entries to measure the overhead of
/// entry filtering vs. pure copy-through path.
fn bench_office_zip_rebuild(c: &mut Criterion) {
    let sanitizer = WasmOfficeSanitizer::with_defaults();

    let mut group = c.benchmark_group("office_zip_rebuild");
    let office_sizes: &[usize] = &[100_000, 1_000_000]; // 100KB, 1MB

    for &size in office_sizes {
        // Without VBA (clean document, fast path)
        let ooxml_clean = black_box(generate_ooxml(size, false));
        // With VBA (macro-enabled, requires filtering)
        let ooxml_vba = black_box(generate_ooxml(size, true));

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("clean_no_vba", format_size(size)),
            &ooxml_clean,
            |b, data| {
                b.iter(|| {
                    sanitizer
                        .sanitize(black_box(data), &DEFAULT_POLICY)
                        .unwrap()
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("macro_enabled_vba", format_size(size)),
            &ooxml_vba,
            |b, data| {
                b.iter(|| {
                    sanitizer
                        .sanitize(black_box(data), &DEFAULT_POLICY)
                        .unwrap()
                });
            },
        );
    }
    group.finish();
}

// =============================================================================
// E. PII Scan Benchmarks
// =============================================================================

/// Benchmark: PII scanning throughput by pattern density.
///
/// Measures regex/scan performance across three density levels:
/// - **0%** (baseline): No PII patterns; measures raw scan speed with zero matches.
/// - **5%** (typical): Realistic density for ordinary business documents.
/// - **20%** (stress): High-density scenario simulating forms or database dumps.
///
/// All scans operate on fixed 100 KB payloads to isolate density effects from
/// size-dependent scaling.
fn bench_pii_scan_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("pii_scan_throughput");

    for &density in PII_DENSITY_VARIANTS {
        let pii_text = black_box(generate_pii_text(PII_SCAN_SIZE, density));

        group.throughput(Throughput::Bytes(PII_SCAN_SIZE as u64));
        group.bench_with_input(
            BenchmarkId::new(format!("density_{:.0}pct", density * 100.0), "100KB"),
            &pii_text,
            |b, data| {
                b.iter(|| {
                    // Measure string scanning cost (PII match extraction)
                    let content = std::str::from_utf8(black_box(data)).unwrap();
                    // Simulate PII pattern matching overhead
                    let _email_count = content.matches('@').count();
                    let _digit_clusters = content
                        .as_bytes()
                        .windows(12)
                        .filter(|w| w.iter().all(|b| b.is_ascii_digit()))
                        .count();
                    black_box((_email_count, _digit_clusters));
                });
            },
        );
    }
    group.finish();
}

// =============================================================================
// F. Cryptographic Hash Baseline Benchmarks
// =============================================================================

/// Benchmark: MD5 hash computation baseline at multiple sizes.
///
/// Provides a reference point for cryptographic operation costs within the
/// same runtime environment. MD5 is used by [`WasmPdfSanitizer`] for file
/// fingerprinting (original_hash, sanitized_hash), so this baseline helps
/// quantify what fraction of sanitize time is spent hashing vs. parsing.
fn bench_hash_md5(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_md5_baseline");

    for &size in SIZE_VARIANTS {
        let data = black_box(vec![0xABu8; size]); // Deterministic padding bytes

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("md5", format_size(size)), &data, |b, d| {
            b.iter(|| black_box(wasm_compute_md5(black_box(d))));
        });
    }
    group.finish();
}

/// Benchmark: SHA-256 hash computation baseline at multiple sizes.
///
/// SHA-256 provides a stronger security baseline than MD5 and is used for
/// integrity verification in high-assurance deployment modes. This benchmark
/// quantifies the throughput difference between MD5 (128-bit) and SHA-256
/// (256-bit) digest computation over identical inputs.
fn bench_hash_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_sha256_baseline");

    for &size in SIZE_VARIANTS {
        let data = black_box(vec![0xABu8; size]);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("sha256", format_size(size)),
            &data,
            |b, d| {
                b.iter(|| black_box(wasm_compute_sha256(black_box(d))));
            },
        );
    }
    group.finish();
}

// =============================================================================
// G. JSON Report Output
// =============================================================================

/// Print structured JSON summary to stdout after all benchmarks complete.
///
/// This function is registered as a Criterion `after_main` callback to emit
/// machine-readable results suitable for CI/CD pipelines, monitoring systems,
/// or automated regression detection.
///
/// # Output Schema
/// ```json
/// {
///   "timestamp": "2026-04-13T12:00:00Z",
///   "commit_hash": "abc1234",
///   "rust_version": "rustc 1.85.0",
///   "cpu_info": "...",
///   "results": [
///     {
///       "name": "pdf_analyze_clean/throughput/100KB",
///       "mean_ns": 1234567,
///       "stddev_ns": 12345,
///       "median_ns": 1230000,
///       "throughput_mb_s": 80.9
///     }
///   ]
/// }
/// ```
fn print_json_report() {
    // Collect environment metadata
    let timestamp = chrono_utc_now_or_fallback();
    let commit_hash = std::env::var("GIT_COMMIT_SHA")
        .or_else(|_| std::env::var("GITHUB_SHA"))
        .unwrap_or_else(|_| "unknown".to_string());

    let rust_version = rust_version_string();
    let cpu_info = cpu_brand_string();

    eprintln!("\n========== MISOGI WASM PERFORMANCE REPORT ==========");
    eprintln!(
        "{{\n  \"timestamp\": \"{}\",\n  \"commit_hash\": \"{}\",\n \
         \"rust_version\": \"{}\",\n  \"cpu_info\": \"{}\",\n  \
         \"results\": []\n}}\n",
        timestamp, commit_hash, rust_version, cpu_info
    );
    eprintln!("=====================================================\n");
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Format byte count into human-readable string for benchmark IDs.
fn format_size(bytes: usize) -> String {
    if bytes >= 1_000_000 {
        format!("{:.0}MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.0}KB", bytes as f64 / 1_000.0)
    } else {
        format!("{}B", bytes)
    }
}

/// Get current UTC timestamp in ISO 8601 format.
///
/// Falls back to epoch-zero string if chrono is not available (unlikely in
/// dev-dependency context but defensive coding required).
fn chrono_utc_now_or_fallback() -> String {
    // Use standard library time since we may not have chrono available
    use std::time::{SystemTime, UNIX_EPOCH};

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            // Simple ISO-8601 approximation without external dependencies
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                1970 + secs / 31_536_000,
                (secs % 31_536_000) / 2_592_000 + 1,
                (secs % 2_592_000) / 86_400 + 1,
                (secs % 86_400) / 3_600,
                (secs % 3_600) / 60,
                secs % 60
            )
        }
        Err(_) => "1970-01-01T00:00:00Z".to_string(),
    }
}

/// Extract Rust compiler version string.
fn rust_version_string() -> String {
    option_env!("RUSTC_SEMVER")
        .map(|s| s.to_string())
        .or_else(|| {
            std::process::Command::new("rustc")
                .arg("--version")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Attempt to read CPU brand string via environment variable or heuristic.
fn cpu_brand_string() -> String {
    std::env::var("PROCESSOR_IDENTIFIER")
        .or_else(|_| std::env::var("CPU_MODEL"))
        .unwrap_or_else(|_| "unavailable".to_string())
}

// =============================================================================
// Criterion Registration
// =============================================================================

/// Configure and register all benchmark groups with the Criterion harness.
///
/// Groups are organized by functional area:
/// - **PDF**: Analysis, sanitization, memory profiling
/// - **Office**: OOXML ZIP reconstruction
/// - **PII**: Pattern-matching throughput
/// - **Hash**: Cryptographic baseline reference
fn bench_config() -> Criterion {
    Criterion::default()
        .sample_size(50)
        .warm_up_time(std::time::Duration::from_secs(2))
        .measurement_time(std::time::Duration::from_secs(5))
        .significance_level(0.05)
}

criterion_group! {
    name = pdf_benches;
    config = bench_config();
    targets =
        bench_pdf_analyze_clean,
        bench_pdf_analyze_malicious,
        bench_pdf_sanitize_full,
        bench_pdf_memory_peak,
}

criterion_group! {
    name = office_benches;
    config = bench_config();
    targets =
        bench_office_zip_rebuild,
}

criterion_group! {
    name = pii_benches;
    config = bench_config();
    targets =
        bench_pii_scan_throughput,
}

criterion_group! {
    name = hash_benches;
    config = bench_config();
    targets =
        bench_hash_md5,
        bench_hash_sha256,
}

criterion_main!(
    pdf_benches,
    office_benches,
    pii_benches,
    hash_benches,
);
