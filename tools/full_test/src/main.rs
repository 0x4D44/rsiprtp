//! `full_test` — orchestrates the rsiprtp test bar and writes an HTML report.
//!
//! See `wrk_docs/2026.05.02 - HLD - full_test runner - V2.md` for the spec.

use chrono::{DateTime, Local};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const EXCL: &[&str] = &[
    "--workspace",
    "--exclude",
    "gabby",
    "--exclude",
    "full_test",
];

#[derive(Debug, Clone)]
struct TestResult {
    name: String,
    passed: bool,
    output: String,
}

#[derive(Debug, Clone)]
struct SuiteResults {
    total: usize,
    passed: usize,
    failed: usize,
    skipped: usize,
    duration: Duration,
    tests: Vec<TestResult>,
}

#[derive(Debug, Clone)]
struct QualityResult {
    check_name: String,
    passed: bool,
    skipped: bool,
    skip_reason: Option<String>,
    duration: Duration,
    issues: Vec<String>,
}

#[derive(Debug, Clone)]
struct DocResult {
    passed: bool,
    duration: Duration,
    stderr_tail: String,
}

#[derive(Debug, Clone)]
struct BuildResult {
    passed: bool,
    duration: Duration,
    stderr_tail: String,
}

#[derive(Debug, Clone)]
struct CoverageMetrics {
    lines_covered: usize,
    lines_total: usize,
    functions_covered: usize,
    functions_total: usize,
    branches_covered: usize,
    branches_total: usize,
    regions_covered: usize,
    regions_total: usize,
    branch_enabled: bool,
    duration: Duration,
}

#[derive(Debug, Clone)]
enum CoverageResult {
    Skipped,
    Failed {
        duration: Duration,
        stderr_tail: String,
    },
    Ok(CoverageMetrics),
}

impl CoverageResult {
    fn passed(&self) -> bool {
        matches!(self, CoverageResult::Ok(_))
    }

    fn is_skipped(&self) -> bool {
        matches!(self, CoverageResult::Skipped)
    }
}

#[derive(Debug, Clone)]
struct CategoryStats {
    name: String,
    total: usize,
    passed: usize,
    failed: usize,
}

#[derive(Debug, Clone, Default)]
struct FullTestOptions {
    skip_quality: bool,
    skip_supply: bool,
    skip_coverage: bool,
}

fn print_help() {
    println!(
        "rsiprtp full test runner

USAGE:
    cargo run --release -p full_test -- [OPTIONS]

OPTIONS:
    --skip-quality    Skip cargo fmt + cargo clippy
    --skip-supply     Skip cargo deny
    --skip-coverage   Skip cargo llvm-cov
    -h, --help        Show this help and exit"
    );
}

fn parse_options(args: &[String]) -> Option<FullTestOptions> {
    let mut opts = FullTestOptions::default();
    for a in args {
        match a.as_str() {
            "--skip-quality" => opts.skip_quality = true,
            "--skip-supply" => opts.skip_supply = true,
            "--skip-coverage" => opts.skip_coverage = true,
            "-h" | "--help" => return None,
            other => {
                eprintln!("unknown flag: {other}");
                return None;
            }
        }
    }
    Some(opts)
}

fn describe_run_mode(o: &FullTestOptions) -> String {
    let mut bits = Vec::new();
    if o.skip_quality {
        bits.push("Quality Skipped");
    }
    if o.skip_supply {
        bits.push("Supply Skipped");
    }
    if o.skip_coverage {
        bits.push("Coverage Skipped");
    }
    if bits.is_empty() {
        "Default".to_string()
    } else {
        format!("Default | {}", bits.join(" | "))
    }
}

fn tool_available(tool: &str) -> bool {
    Command::new("cargo")
        .args([tool, "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn is_nightly_toolchain() -> bool {
    Command::new("rustc")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("nightly"))
        .unwrap_or(false)
}

fn run_quality_check(
    check_name: &str,
    cargo_args: &[&str],
    is_issue: fn(&str) -> bool,
) -> QualityResult {
    run_quality_check_with(check_name, cargo_args, is_issue, None)
}

fn run_quality_check_with(
    check_name: &str,
    cargo_args: &[&str],
    is_issue: fn(&str) -> bool,
    is_transient: Option<fn(&str) -> bool>,
) -> QualityResult {
    let start = Instant::now();
    let output = Command::new("cargo")
        .args(cargo_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute cargo {}: {e}", cargo_args[0]));
    let duration = start.elapsed();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let passed = output.status.success();

    classify_quality_output(
        check_name,
        passed,
        &stdout,
        &stderr,
        duration,
        is_issue,
        is_transient,
    )
}

fn classify_quality_output(
    check_name: &str,
    passed: bool,
    stdout: &str,
    stderr: &str,
    duration: Duration,
    is_issue: fn(&str) -> bool,
    is_transient: Option<fn(&str) -> bool>,
) -> QualityResult {
    if !passed {
        if let Some(detector) = is_transient {
            if detector(stderr) || detector(stdout) {
                return QualityResult {
                    check_name: check_name.to_string(),
                    passed: true,
                    skipped: true,
                    skip_reason: Some("transient".to_string()),
                    duration,
                    issues: Vec::new(),
                };
            }
        }
    }

    let issues: Vec<String> = stdout
        .lines()
        .chain(stderr.lines())
        .map(str::trim)
        .filter(|l| !l.is_empty() && is_issue(l))
        .map(String::from)
        .collect();

    QualityResult {
        check_name: check_name.to_string(),
        passed,
        skipped: false,
        skip_reason: None,
        duration,
        issues,
    }
}

fn skipped_quality(check_name: &str, reason: &str) -> QualityResult {
    QualityResult {
        check_name: check_name.to_string(),
        passed: true,
        skipped: true,
        skip_reason: Some(reason.to_string()),
        duration: Duration::ZERO,
        issues: Vec::new(),
    }
}

fn fmt_is_issue(line: &str) -> bool {
    line.starts_with("Diff in ")
}

fn clippy_is_issue(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("warning: ") || t.starts_with("error:") || t.starts_with("error[")
}

fn deny_is_issue(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("error[") || t.starts_with("warning[") || t.starts_with("error:")
}

fn deny_is_transient(text: &str) -> bool {
    text.contains("failed to fetch") || text.contains("unable to update")
}

fn run_fmt_check() -> QualityResult {
    run_quality_check("cargo fmt", &["fmt", "--check"], fmt_is_issue)
}

fn run_clippy() -> QualityResult {
    let mut args: Vec<&str> = vec!["clippy"];
    args.extend_from_slice(EXCL);
    args.extend_from_slice(&["--all-targets", "--", "-D", "warnings"]);
    run_quality_check("cargo clippy", &args, clippy_is_issue)
}

fn run_cargo_deny() -> QualityResult {
    if !tool_available("deny") {
        return skipped_quality("cargo deny", "not installed");
    }
    run_quality_check_with(
        "cargo deny",
        &["deny", "check"],
        deny_is_issue,
        Some(deny_is_transient),
    )
}

fn run_cargo_test() -> SuiteResults {
    let start = Instant::now();
    let mut args: Vec<&str> = vec!["test"];
    args.extend_from_slice(EXCL);
    args.extend_from_slice(&["--no-fail-fast", "--", "--test-threads=1"]);
    let output = Command::new("cargo")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute cargo test");
    let duration = start.elapsed();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let mut suite = parse_test_output(&stdout, &stderr, duration);

    if !output.status.success() && suite.failed == 0 {
        let status_label = format_exit_status(&output.status);
        record_non_test_cargo_failure(&mut suite, &status_label, &stdout, &stderr);
    }

    suite
}

fn run_cargo_build() -> BuildResult {
    let start = Instant::now();
    let mut args: Vec<&str> = vec!["build"];
    args.extend_from_slice(EXCL);
    args.push("--locked");
    let output = Command::new("cargo")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute cargo build");
    let duration = start.elapsed();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let passed = output.status.success();

    let stderr_tail = if passed {
        String::new()
    } else {
        tail_lines(&stderr, 50)
    };

    BuildResult {
        passed,
        duration,
        stderr_tail,
    }
}

fn run_doc() -> DocResult {
    let start = Instant::now();
    let mut args: Vec<&str> = vec!["doc"];
    args.extend_from_slice(EXCL);
    args.push("--no-deps");
    let output = Command::new("cargo")
        .args(&args)
        .env("RUSTDOCFLAGS", "-D warnings")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute cargo doc");
    let duration = start.elapsed();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let passed = output.status.success();

    let stderr_tail = if passed {
        String::new()
    } else {
        let lines: Vec<&str> = stderr.lines().collect();
        let start_idx = lines.len().saturating_sub(50);
        lines[start_idx..].join("\n")
    };

    DocResult {
        passed,
        duration,
        stderr_tail,
    }
}

fn run_coverage() -> CoverageResult {
    if !tool_available("llvm-cov") {
        return CoverageResult::Skipped;
    }
    let use_branch = is_nightly_toolchain();
    let start = Instant::now();

    let mut args: Vec<&str> = vec!["llvm-cov"];
    args.extend_from_slice(EXCL);
    if use_branch {
        args.push("--branch");
    }
    args.extend_from_slice(&["--json", "--no-cfg-coverage"]);

    let output = match Command::new("cargo")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return CoverageResult::Failed {
                duration: start.elapsed(),
                stderr_tail: format!("failed to spawn cargo llvm-cov: {e}"),
            };
        }
    };
    let duration = start.elapsed();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return CoverageResult::Failed {
            duration,
            stderr_tail: tail_lines(&stderr, 50),
        };
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    match parse_coverage_json(&stdout, duration, use_branch) {
        Some(m) => CoverageResult::Ok(m),
        None => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            CoverageResult::Failed {
                duration,
                stderr_tail: format!(
                    "could not parse llvm-cov JSON output\n\nstderr (last lines):\n{}",
                    tail_lines(&stderr, 50)
                ),
            }
        }
    }
}

fn tail_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

fn parse_coverage_json(
    json: &str,
    duration: Duration,
    branch_enabled: bool,
) -> Option<CoverageMetrics> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let totals = value.get("data")?.as_array()?.first()?.get("totals")?;
    let metric = |section: &str, key: &str| -> usize {
        totals
            .get(section)
            .and_then(|s| s.get(key))
            .and_then(serde_json::Value::as_u64)
            .map(|n| n as usize)
            .unwrap_or(0)
    };
    Some(CoverageMetrics {
        lines_covered: metric("lines", "covered"),
        lines_total: metric("lines", "count"),
        functions_covered: metric("functions", "covered"),
        functions_total: metric("functions", "count"),
        branches_covered: metric("branches", "covered"),
        branches_total: metric("branches", "count"),
        regions_covered: metric("regions", "covered"),
        regions_total: metric("regions", "count"),
        branch_enabled,
        duration,
    })
}

fn parse_test_output(stdout: &str, stderr: &str, duration: Duration) -> SuiteResults {
    let mut tests = Vec::new();
    let mut total = 0;
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for line in stdout.lines().chain(stderr.lines()) {
        if line.starts_with("test ")
            && (line.contains(" ... ok")
                || line.contains(" ... FAILED")
                || line.contains(" ... ignored"))
        {
            let parts: Vec<&str> = line.split(" ... ").collect();
            if parts.len() < 2 {
                continue;
            }
            let name = parts[0].trim_start_matches("test ").to_string();
            let status = parts[1].trim();

            total += 1;
            let test_passed = match status {
                "ok" => {
                    passed += 1;
                    true
                }
                "FAILED" => {
                    failed += 1;
                    false
                }
                "ignored" => {
                    skipped += 1;
                    continue;
                }
                _ => continue,
            };

            tests.push(TestResult {
                name,
                passed: test_passed,
                output: String::new(),
            });
        }
    }

    SuiteResults {
        total,
        passed,
        failed,
        skipped,
        duration,
        tests,
    }
}

fn format_exit_status(status: &std::process::ExitStatus) -> String {
    status.code().map_or_else(
        || "terminated without an exit code".to_string(),
        |code| format!("exit code {code}"),
    )
}

fn record_non_test_cargo_failure(
    results: &mut SuiteResults,
    status_label: &str,
    stdout: &str,
    stderr: &str,
) {
    let completed: HashSet<&str> = stdout
        .lines()
        .chain(stderr.lines())
        .filter_map(|line| {
            if line.starts_with("test ")
                && (line.contains(" ... ok")
                    || line.contains(" ... FAILED")
                    || line.contains(" ... ignored"))
            {
                line.split(" ... ")
                    .next()
                    .map(|s| s.trim_start_matches("test "))
            } else {
                None
            }
        })
        .collect();

    let in_flight: Vec<&str> = stdout
        .lines()
        .chain(stderr.lines())
        .filter_map(|line| {
            if line.starts_with("test ")
                && !line.starts_with("test result:")
                && !line.contains(" ... ")
            {
                Some(line.trim_start_matches("test ").trim())
            } else if line.starts_with("test ") && line.ends_with(" ...") {
                let name = line.trim_start_matches("test ").trim_end_matches(" ...");
                if !completed.contains(name) {
                    Some(name)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    let mut output = format!(
        "cargo test exited non-zero ({status_label}) without reporting individual test failures.\n"
    );
    if !in_flight.is_empty() {
        output.push_str("\nIn-flight tests (running when process crashed):\n");
        for name in &in_flight {
            output.push_str(&format!("  - {name}\n"));
        }
    }

    const MAX_LINES: usize = 50;
    if !stderr.trim().is_empty() {
        output.push_str("\nstderr (last lines):\n");
        let lines: Vec<&str> = stderr.lines().collect();
        let s = lines.len().saturating_sub(MAX_LINES);
        for line in &lines[s..] {
            output.push_str(line);
            output.push('\n');
        }
    }
    if !stdout.trim().is_empty() {
        output.push_str("\nstdout (last lines):\n");
        let lines: Vec<&str> = stdout.lines().collect();
        let s = lines.len().saturating_sub(MAX_LINES);
        for line in &lines[s..] {
            output.push_str(line);
            output.push('\n');
        }
    }

    results.total += 1;
    results.failed += 1;
    results.tests.push(TestResult {
        name: "cargo::test::process_failure".to_string(),
        passed: false,
        output,
    });
}

fn category_for(test_name: &str) -> &'static str {
    if test_name.contains("(line ") {
        return "Doc tests";
    }
    let head = test_name.split("::").next().unwrap_or("");
    match head {
        "sip" => "SIP",
        "transport" => "Transport",
        "transaction" => "Transaction",
        "dialog" => "Dialog",
        "session" => "Session",
        "sdp" => "SDP",
        "rtp" => "RTP",
        "srtp" => "SRTP",
        "ice" => "ICE",
        "media" => "Media",
        "core" => "Core",
        _ => "Integration",
    }
}

fn categorize_tests(tests: &[TestResult]) -> Vec<CategoryStats> {
    use std::collections::BTreeMap;
    let mut by_cat: BTreeMap<&'static str, CategoryStats> = BTreeMap::new();
    for t in tests {
        let cat = category_for(&t.name);
        let entry = by_cat.entry(cat).or_insert_with(|| CategoryStats {
            name: cat.to_string(),
            total: 0,
            passed: 0,
            failed: 0,
        });
        entry.total += 1;
        if t.passed {
            entry.passed += 1;
        } else {
            entry.failed += 1;
        }
    }
    let mut out: Vec<CategoryStats> = by_cat.into_values().collect();
    out.sort_by(|a, b| b.failed.cmp(&a.failed).then(a.name.cmp(&b.name)));
    out
}

fn build_report_path(now: DateTime<Local>, dir: &Path) -> PathBuf {
    let date = now.format("%Y.%m.%d");
    let base = dir.join(format!("{date} - full test report.html"));
    if !base.exists() {
        return base;
    }
    for n in 2.. {
        let path = dir.join(format!("{date} - full test report ({n}).html"));
        if !path.exists() {
            return path;
        }
    }
    unreachable!()
}

fn write_report(report_path: &Path, report: &str) -> std::io::Result<()> {
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(report_path, report)
}

fn results_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("crates")
        .join("rsiprtp")
        .join("tests")
        .join("results")
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn get_git_info() -> String {
    let hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            o.status
                .success()
                .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    let branch = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            o.status
                .success()
                .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    format!("{hash} ({branch})")
}

#[allow(clippy::too_many_arguments)]
fn generate_html_report(
    fmt_result: Option<&QualityResult>,
    clippy_result: Option<&QualityResult>,
    deny_result: Option<&QualityResult>,
    build_result: Option<&BuildResult>,
    test_result: Option<&SuiteResults>,
    doc_result: Option<&DocResult>,
    coverage_result: Option<&CoverageResult>,
    git_info: &str,
    now: DateTime<Local>,
    run_mode: &str,
) -> String {
    let timestamp = now.format("%Y.%m.%d %H:%M:%S").to_string();

    let mut total_passed: usize = 0;
    let mut total_failed: usize = 0;
    let mut total_skipped: usize = 0;

    let quality_passes = [fmt_result, clippy_result, deny_result];
    for q in quality_passes.iter().flatten() {
        if q.skipped {
            total_skipped += 1;
        } else if q.passed {
            total_passed += 1;
        } else {
            total_failed += 1;
        }
    }
    if let Some(r) = build_result {
        if r.passed {
            total_passed += 1;
        } else {
            total_failed += 1;
        }
    }
    if let Some(r) = test_result {
        total_passed += r.passed;
        total_failed += r.failed;
        total_skipped += r.skipped;
    }
    if let Some(r) = doc_result {
        if r.passed {
            total_passed += 1;
        } else {
            total_failed += 1;
        }
    }
    if let Some(r) = coverage_result {
        match r {
            CoverageResult::Skipped => {}
            CoverageResult::Failed { .. } => total_failed += 1,
            CoverageResult::Ok(_) => total_passed += 1,
        }
    }

    let mut html = String::with_capacity(64 * 1024);
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"utf-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    html.push_str("<title>rsiprtp Full Test Report</title>\n");
    html.push_str("<style>\n");
    html.push_str(STYLE_CSS);
    html.push_str("</style>\n");
    html.push_str("</head>\n<body>\n<div class=\"container\">\n");

    html.push_str("<h1>rsiprtp Full Test Report</h1>\n");
    html.push_str(&format!(
        "<p class=\"meta\">{} | commit {}</p>\n",
        html_escape(&timestamp),
        html_escape(git_info),
    ));
    html.push_str(&format!(
        "<p class=\"run-mode\"><strong>Run mode:</strong> {}</p>\n",
        html_escape(run_mode),
    ));

    html.push_str("<div class=\"dashboard\">\n");
    html.push_str(&format!(
        "  <div class=\"card pass\"><div class=\"number\">{total_passed}</div><div class=\"label\">Passed</div></div>\n"
    ));
    html.push_str(&format!(
        "  <div class=\"card fail\"><div class=\"number\">{total_failed}</div><div class=\"label\">Failed</div></div>\n"
    ));
    html.push_str(&format!(
        "  <div class=\"card skip\"><div class=\"number\">{total_skipped}</div><div class=\"label\">Skipped</div></div>\n"
    ));
    html.push_str("</div>\n");

    html.push_str("<h2>Summary</h2>\n");
    html.push_str(
        "<table>\n<tr><th>Pass</th><th>Status</th><th>Passed</th><th>Failed</th><th>Skipped</th><th>Duration</th></tr>\n",
    );
    for q in quality_passes.iter().flatten() {
        write_quality_row(&mut html, q);
    }
    if let Some(r) = build_result {
        let (status_class, status_text, p, f) = if r.passed {
            ("status-pass", "PASS", "1", "0")
        } else {
            ("status-fail", "FAIL", "0", "1")
        };
        html.push_str(&format!(
            "<tr><td>cargo build</td><td class=\"{}\">{}</td><td>{}</td><td>{}</td><td>0</td><td>{:.2}s</td></tr>\n",
            status_class,
            status_text,
            p,
            f,
            r.duration.as_secs_f64()
        ));
    }
    if let Some(r) = test_result {
        let (status_class, status_text) = if r.failed == 0 {
            ("status-pass", "PASS")
        } else {
            ("status-fail", "FAIL")
        };
        html.push_str(&format!(
            "<tr><td>cargo test</td><td class=\"{}\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.2}s</td></tr>\n",
            status_class,
            status_text,
            r.passed,
            r.failed,
            r.skipped,
            r.duration.as_secs_f64()
        ));
    }
    if let Some(r) = doc_result {
        let (status_class, status_text, p, f) = if r.passed {
            ("status-pass", "PASS", "1", "0")
        } else {
            ("status-fail", "FAIL", "0", "1")
        };
        html.push_str(&format!(
            "<tr><td>cargo doc</td><td class=\"{}\">{}</td><td>{}</td><td>{}</td><td>0</td><td>{:.2}s</td></tr>\n",
            status_class,
            status_text,
            p,
            f,
            r.duration.as_secs_f64()
        ));
    }
    if let Some(r) = coverage_result {
        match r {
            CoverageResult::Skipped => {}
            CoverageResult::Ok(m) => html.push_str(&format!(
                "<tr><td>cargo llvm-cov</td><td class=\"status-pass\">PASS</td><td>1</td><td>0</td><td>0</td><td>{:.2}s</td></tr>\n",
                m.duration.as_secs_f64()
            )),
            CoverageResult::Failed { duration, .. } => html.push_str(&format!(
                "<tr><td>cargo llvm-cov</td><td class=\"status-fail\">FAIL</td><td>0</td><td>1</td><td>0</td><td>{:.2}s</td></tr>\n",
                duration.as_secs_f64()
            )),
        }
    }
    html.push_str("</table>\n");

    let any_quality = quality_passes.iter().any(|q| q.is_some());
    if any_quality {
        html.push_str("<h2>Code Quality</h2>\n");
        for q in quality_passes.iter().flatten() {
            write_quality_section(&mut html, q);
        }
    }

    if let Some(r) = test_result {
        let cats = categorize_tests(&r.tests);
        if !cats.is_empty() {
            html.push_str("<h2>Test Breakdown by Category</h2>\n");
            html.push_str(
                "<table>\n<tr><th>Category</th><th>Total</th><th>Passed</th><th>Failed</th></tr>\n",
            );
            for c in &cats {
                let fail_class = if c.failed > 0 {
                    " class=\"status-fail\""
                } else {
                    ""
                };
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td{}>{}</td></tr>\n",
                    html_escape(&c.name),
                    c.total,
                    c.passed,
                    fail_class,
                    c.failed,
                ));
            }
            html.push_str("</table>\n");
        }

        let failed_tests: Vec<&TestResult> = r.tests.iter().filter(|t| !t.passed).collect();
        if !failed_tests.is_empty() {
            html.push_str("<h2>Failed Tests</h2>\n");
            html.push_str("<ul class=\"test-list\">\n");
            for t in &failed_tests {
                html.push_str(&format!(
                    "<li class=\"fail\"><code>{}</code></li>\n",
                    html_escape(&t.name)
                ));
            }
            html.push_str("</ul>\n");
            for t in &failed_tests {
                if !t.output.is_empty() {
                    html.push_str(&format!(
                        "<details><summary><code>{}</code></summary><pre>{}</pre></details>\n",
                        html_escape(&t.name),
                        html_escape(&t.output),
                    ));
                }
            }
        }
    }

    match coverage_result {
        Some(CoverageResult::Ok(r)) => {
            html.push_str("<h2>Coverage</h2>\n");
            html.push_str(
                "<table>\n<tr><th>Metric</th><th>Covered</th><th>Total</th><th>Percent</th></tr>\n",
            );
            write_cov_row(&mut html, "Lines", r.lines_covered, r.lines_total);
            write_cov_row(
                &mut html,
                "Functions",
                r.functions_covered,
                r.functions_total,
            );
            write_cov_row(&mut html, "Regions", r.regions_covered, r.regions_total);
            if r.branch_enabled {
                write_cov_row(&mut html, "Branches", r.branches_covered, r.branches_total);
            }
            html.push_str("</table>\n");
        }
        Some(CoverageResult::Failed { stderr_tail, .. }) => {
            html.push_str("<h2>Coverage</h2>\n");
            html.push_str("<p class=\"status-fail\">cargo llvm-cov FAILED</p>\n");
            html.push_str(&format!("<pre>{}</pre>\n", html_escape(stderr_tail)));
        }
        Some(CoverageResult::Skipped) | None => {}
    }

    if let Some(r) = build_result {
        if !r.passed {
            html.push_str("<h2>Build</h2>\n");
            html.push_str("<p class=\"status-fail\">cargo build FAILED</p>\n");
            html.push_str(&format!("<pre>{}</pre>\n", html_escape(&r.stderr_tail)));
        }
    }

    if let Some(r) = doc_result {
        if !r.passed {
            html.push_str("<h2>Doc Build</h2>\n");
            html.push_str("<p class=\"status-fail\">cargo doc FAILED</p>\n");
            html.push_str(&format!("<pre>{}</pre>\n", html_escape(&r.stderr_tail)));
        }
    }

    html.push_str("<footer>Generated by rsiprtp full_test runner</footer>\n");
    html.push_str("</div>\n</body>\n</html>\n");
    html
}

fn write_quality_row(html: &mut String, q: &QualityResult) {
    if q.skipped {
        let reason = q.skip_reason.as_deref().unwrap_or("skipped");
        html.push_str(&format!(
            "<tr><td>{}</td><td>SKIP ({})</td><td>0</td><td>0</td><td>1</td><td>-</td></tr>\n",
            html_escape(&q.check_name),
            html_escape(reason),
        ));
        return;
    }
    let (status_class, status_text, p, f) = if q.passed {
        ("status-pass", "PASS", "1", "0")
    } else {
        ("status-fail", "FAIL", "0", "1")
    };
    html.push_str(&format!(
        "<tr><td>{}</td><td class=\"{}\">{}</td><td>{}</td><td>{}</td><td>0</td><td>{:.2}s</td></tr>\n",
        html_escape(&q.check_name),
        status_class,
        status_text,
        p,
        f,
        q.duration.as_secs_f64()
    ));
}

fn write_quality_section(html: &mut String, q: &QualityResult) {
    if q.skipped {
        let reason = q.skip_reason.as_deref().unwrap_or("skipped");
        html.push_str(&format!(
            "<p><strong>{}</strong>: SKIP ({})</p>\n",
            html_escape(&q.check_name),
            html_escape(reason),
        ));
        return;
    }
    let badge = if q.passed { "pass-badge" } else { "fail-badge" };
    let label = if q.passed { "PASS" } else { "FAIL" };
    html.push_str(&format!(
        "<p><strong>{}</strong> <span class=\"{}\">{}</span> in {:.2}s</p>\n",
        html_escape(&q.check_name),
        badge,
        label,
        q.duration.as_secs_f64()
    ));
    if !q.passed && !q.issues.is_empty() {
        html.push_str("<ul>\n");
        for line in q.issues.iter().take(20) {
            html.push_str(&format!("<li><code>{}</code></li>\n", html_escape(line)));
        }
        if q.issues.len() > 20 {
            html.push_str(&format!("<li>... and {} more</li>\n", q.issues.len() - 20));
        }
        html.push_str("</ul>\n");
    }
}

fn write_cov_row(html: &mut String, name: &str, covered: usize, total: usize) {
    let pct = if total > 0 {
        covered as f64 / total as f64 * 100.0
    } else {
        0.0
    };
    html.push_str(&format!(
        "<tr><td>{name}</td><td>{covered}</td><td>{total}</td><td>{pct:.1}%</td></tr>\n"
    ));
}

#[allow(clippy::too_many_arguments)]
fn generate_markdown_report(
    fmt_result: Option<&QualityResult>,
    clippy_result: Option<&QualityResult>,
    deny_result: Option<&QualityResult>,
    build_result: Option<&BuildResult>,
    test_result: Option<&SuiteResults>,
    doc_result: Option<&DocResult>,
    coverage_result: Option<&CoverageResult>,
    git_info: &str,
    now: DateTime<Local>,
    run_mode: &str,
) -> String {
    let timestamp = now.format("%Y.%m.%d %H:%M:%S").to_string();
    let mut md = String::new();
    md.push_str("# rsiprtp Full Test Report\n\n");
    md.push_str(&format!("{timestamp} | commit {git_info}\n\n"));
    md.push_str(&format!("Run mode: {run_mode}\n\n"));

    md.push_str("## Summary\n\n");
    md.push_str("| Pass | Status | Duration |\n");
    md.push_str("|------|--------|----------|\n");
    let qps = [fmt_result, clippy_result, deny_result];
    for q in qps.iter().flatten() {
        let status = if q.skipped {
            format!("SKIP ({})", q.skip_reason.as_deref().unwrap_or(""))
        } else if q.passed {
            "PASS".to_string()
        } else {
            "FAIL".to_string()
        };
        md.push_str(&format!(
            "| {} | {} | {:.2}s |\n",
            q.check_name,
            status,
            q.duration.as_secs_f64()
        ));
    }
    if let Some(r) = build_result {
        let status = if r.passed { "PASS" } else { "FAIL" };
        md.push_str(&format!(
            "| cargo build | {} | {:.2}s |\n",
            status,
            r.duration.as_secs_f64()
        ));
    }
    if let Some(r) = test_result {
        let status = if r.failed == 0 { "PASS" } else { "FAIL" };
        md.push_str(&format!(
            "| cargo test | {} ({}/{} passed, {} failed, {} skipped) | {:.2}s |\n",
            status,
            r.passed,
            r.total - r.skipped,
            r.failed,
            r.skipped,
            r.duration.as_secs_f64()
        ));
    }
    if let Some(r) = doc_result {
        let status = if r.passed { "PASS" } else { "FAIL" };
        md.push_str(&format!(
            "| cargo doc | {} | {:.2}s |\n",
            status,
            r.duration.as_secs_f64()
        ));
    }
    if let Some(r) = coverage_result {
        match r {
            CoverageResult::Skipped => {}
            CoverageResult::Ok(m) => {
                let pct = if m.lines_total > 0 {
                    m.lines_covered as f64 / m.lines_total as f64 * 100.0
                } else {
                    0.0
                };
                md.push_str(&format!(
                    "| cargo llvm-cov | PASS ({:.1}% lines) | {:.2}s |\n",
                    pct,
                    m.duration.as_secs_f64()
                ));
            }
            CoverageResult::Failed { duration, .. } => {
                md.push_str(&format!(
                    "| cargo llvm-cov | FAIL | {:.2}s |\n",
                    duration.as_secs_f64()
                ));
            }
        }
    }
    md.push('\n');

    if let Some(r) = test_result {
        let cats = categorize_tests(&r.tests);
        if !cats.is_empty() {
            md.push_str("## Test Breakdown by Category\n\n");
            md.push_str("| Category | Total | Passed | Failed |\n");
            md.push_str("|----------|-------|--------|--------|\n");
            for c in &cats {
                md.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    c.name, c.total, c.passed, c.failed
                ));
            }
            md.push('\n');
        }
        let failed: Vec<&TestResult> = r.tests.iter().filter(|t| !t.passed).collect();
        if !failed.is_empty() {
            md.push_str("## Failed Tests\n\n");
            for t in &failed {
                md.push_str(&format!("- `{}`\n", t.name));
            }
            md.push('\n');
        }
    }

    if let Some(CoverageResult::Ok(r)) = coverage_result {
        md.push_str("## Coverage\n\n");
        md.push_str("| Metric | Covered | Total | Percent |\n");
        md.push_str("|--------|---------|-------|---------|\n");
        let rows: &[(&str, usize, usize)] = &[
            ("Lines", r.lines_covered, r.lines_total),
            ("Functions", r.functions_covered, r.functions_total),
            ("Regions", r.regions_covered, r.regions_total),
        ];
        for (n, c, t) in rows {
            let pct = if *t > 0 {
                *c as f64 / *t as f64 * 100.0
            } else {
                0.0
            };
            md.push_str(&format!("| {n} | {c} | {t} | {pct:.1}% |\n"));
        }
        if r.branch_enabled {
            let pct = if r.branches_total > 0 {
                r.branches_covered as f64 / r.branches_total as f64 * 100.0
            } else {
                0.0
            };
            md.push_str(&format!(
                "| Branches | {} | {} | {pct:.1}% |\n",
                r.branches_covered, r.branches_total
            ));
        }
        md.push('\n');
    }

    md
}

fn print_pass_heartbeat(idx: usize, total: usize, label: &str) {
    print!("[{idx}/{total}] {label} ... ");
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

fn print_pass_result(line: &str) {
    println!("{line}");
}

fn quality_line(q: &QualityResult) -> String {
    if q.skipped {
        format!("SKIP ({})", q.skip_reason.as_deref().unwrap_or("skipped"))
    } else if q.passed {
        format!("PASS in {:.1}s", q.duration.as_secs_f64())
    } else {
        format!(
            "FAIL ({} issues) in {:.1}s",
            q.issues.len(),
            q.duration.as_secs_f64()
        )
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match parse_options(&args) {
        Some(o) => o,
        None => {
            print_help();
            std::process::exit(0);
        }
    };

    println!("=== rsiprtp Full Test Suite ===\n");

    let total_passes = 7;
    let now = Local::now();

    let mut fmt_res: Option<QualityResult> = None;
    let mut clippy_res: Option<QualityResult> = None;
    let mut deny_res: Option<QualityResult> = None;
    let mut coverage_res: Option<CoverageResult> = None;

    if !opts.skip_quality {
        print_pass_heartbeat(1, total_passes, "cargo fmt --check");
        let r = run_fmt_check();
        print_pass_result(&quality_line(&r));
        fmt_res = Some(r);

        print_pass_heartbeat(2, total_passes, "cargo clippy");
        let r = run_clippy();
        print_pass_result(&quality_line(&r));
        clippy_res = Some(r);
    } else {
        println!("[1/{total_passes}] cargo fmt --check ... SKIP (--skip-quality)");
        println!("[2/{total_passes}] cargo clippy ... SKIP (--skip-quality)");
    }

    if !opts.skip_supply {
        print_pass_heartbeat(3, total_passes, "cargo deny check");
        let r = run_cargo_deny();
        print_pass_result(&quality_line(&r));
        deny_res = Some(r);
    } else {
        println!("[3/{total_passes}] cargo deny check ... SKIP (--skip-supply)");
    }

    print_pass_heartbeat(4, total_passes, "cargo build --locked");
    let build_inner = run_cargo_build();
    println!(
        "{} in {:.1}s",
        if build_inner.passed { "PASS" } else { "FAIL" },
        build_inner.duration.as_secs_f64()
    );
    let build_res: Option<BuildResult> = Some(build_inner);

    print_pass_heartbeat(5, total_passes, "cargo test");
    println!("running...");
    let test_inner = run_cargo_test();
    println!(
        "       {} in {:.1}s ({} / {})",
        if test_inner.failed == 0 {
            "PASS"
        } else {
            "FAIL"
        },
        test_inner.duration.as_secs_f64(),
        test_inner.passed,
        test_inner.total - test_inner.skipped,
    );
    let test_res: Option<SuiteResults> = Some(test_inner);

    print_pass_heartbeat(6, total_passes, "cargo doc --no-deps");
    let doc_inner = run_doc();
    println!(
        "{} in {:.1}s",
        if doc_inner.passed { "PASS" } else { "FAIL" },
        doc_inner.duration.as_secs_f64()
    );
    let doc_res: Option<DocResult> = Some(doc_inner);

    if !opts.skip_coverage {
        print_pass_heartbeat(7, total_passes, "cargo llvm-cov");
        println!("running...");
        let r = run_coverage();
        match &r {
            CoverageResult::Skipped => println!("       SKIP (not installed)"),
            CoverageResult::Ok(m) => {
                let pct = if m.lines_total > 0 {
                    m.lines_covered as f64 / m.lines_total as f64 * 100.0
                } else {
                    0.0
                };
                println!(
                    "       {:.1}% lines in {:.1}s",
                    pct,
                    m.duration.as_secs_f64()
                );
            }
            CoverageResult::Failed { duration, .. } => {
                println!("       FAIL in {:.1}s", duration.as_secs_f64());
            }
        }
        if !matches!(r, CoverageResult::Skipped) {
            coverage_res = Some(r);
        }
    } else {
        println!("[7/{total_passes}] cargo llvm-cov ... SKIP (--skip-coverage)");
    }

    let git_info = get_git_info();
    let run_mode = describe_run_mode(&opts);

    let html = generate_html_report(
        fmt_res.as_ref(),
        clippy_res.as_ref(),
        deny_res.as_ref(),
        build_res.as_ref(),
        test_res.as_ref(),
        doc_res.as_ref(),
        coverage_res.as_ref(),
        &git_info,
        now,
        &run_mode,
    );

    let dir = results_dir();
    let report_path = build_report_path(now, &dir);
    if let Err(e) = write_report(&report_path, &html) {
        eprintln!("Failed to write report: {e}");
        std::process::exit(2);
    }

    let md = generate_markdown_report(
        fmt_res.as_ref(),
        clippy_res.as_ref(),
        deny_res.as_ref(),
        build_res.as_ref(),
        test_res.as_ref(),
        doc_res.as_ref(),
        coverage_res.as_ref(),
        &git_info,
        now,
        &run_mode,
    );
    println!("\n{md}");
    println!("Report saved to: {}", report_path.display());

    let mut overall_ok = true;
    for q in [fmt_res.as_ref(), clippy_res.as_ref(), deny_res.as_ref()]
        .iter()
        .flatten()
    {
        if !q.skipped && !q.passed {
            overall_ok = false;
        }
    }
    if let Some(r) = build_res.as_ref() {
        if !r.passed {
            overall_ok = false;
        }
    }
    if let Some(r) = test_res.as_ref() {
        if r.failed > 0 {
            overall_ok = false;
        }
    }
    if let Some(r) = doc_res.as_ref() {
        if !r.passed {
            overall_ok = false;
        }
    }
    if let Some(r) = coverage_res.as_ref() {
        if !r.is_skipped() && !r.passed() {
            overall_ok = false;
        }
    }

    std::process::exit(if overall_ok { 0 } else { 1 });
}

const STYLE_CSS: &str = r#":root {
  --bg: #ffffff; --fg: #1a1a2e; --card-bg: #f8f9fa; --border: #dee2e6;
  --table-alt: #f8f9fa; --table-border: #dee2e6;
  --pass-bg: #dcfce7; --pass-fg: #166534;
  --fail-bg: #fee2e2; --fail-fg: #991b1b;
  --skip-bg: #fef9c3; --skip-fg: #854d0e;
  --link: #2563eb; --meta: #6b7280;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1a1a2e; --fg: #e0e0e0; --card-bg: #16213e; --border: #374151;
    --table-alt: #16213e; --table-border: #374151;
    --pass-bg: #064e3b; --pass-fg: #6ee7b7;
    --fail-bg: #7f1d1d; --fail-fg: #fca5a5;
    --skip-bg: #78350f; --skip-fg: #fde68a;
    --link: #60a5fa; --meta: #9ca3af;
  }
}
* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: var(--bg); color: var(--fg);
  margin: 0; padding: 20px; line-height: 1.6;
}
.container { max-width: 1200px; margin: 0 auto; }
h1 { margin: 0 0 4px 0; }
h2 { margin-top: 32px; border-bottom: 2px solid var(--border); padding-bottom: 8px; }
.meta { color: var(--meta); margin: 0 0 24px 0; }
.run-mode { font-size: 1.1em; margin: 0 0 16px 0; padding: 8px 12px; background: var(--card-bg); border-radius: 4px; }
.dashboard { display: flex; gap: 16px; flex-wrap: wrap; margin: 16px 0 24px 0; }
.card {
  display: inline-block; min-width: 120px; padding: 16px 24px;
  border-radius: 8px; text-align: center;
}
.card .number { font-size: 2em; font-weight: bold; }
.card .label { font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; }
.card.pass { background: var(--pass-bg); color: var(--pass-fg); }
.card.fail { background: var(--fail-bg); color: var(--fail-fg); }
.card.skip { background: var(--skip-bg); color: var(--skip-fg); }
table { width: 100%; border-collapse: collapse; margin: 12px 0; }
th, td { padding: 8px 12px; text-align: left; border: 1px solid var(--table-border); }
th { background: var(--card-bg); font-weight: 600; }
tr:nth-child(even) td { background: var(--table-alt); }
.status-pass { background: var(--pass-bg); color: var(--pass-fg); font-weight: 600; }
.status-fail { background: var(--fail-bg); color: var(--fail-fg); font-weight: 600; }
details { padding: 4px 0; border-bottom: 1px solid var(--border); }
details summary { cursor: pointer; padding: 8px 0; font-weight: 500; }
details summary:hover { color: var(--link); }
pre { background: var(--card-bg); padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 0.85em; }
.fail-badge {
  background: var(--fail-bg); color: var(--fail-fg);
  padding: 2px 8px; border-radius: 4px; font-size: 0.85em; margin-left: 8px;
}
.pass-badge {
  background: var(--pass-bg); color: var(--pass-fg);
  padding: 2px 8px; border-radius: 4px; font-size: 0.85em; margin-left: 8px;
}
ul.test-list { list-style: none; padding-left: 16px; margin: 4px 0; }
ul.test-list li { padding: 2px 4px; font-family: monospace; font-size: 0.9em; }
ul.test-list li.pass::before { content: '\2713 '; color: #22c55e; }
ul.test-list li.fail::before { content: '\2717 '; color: #ef4444; }
footer {
  margin-top: 48px; padding-top: 16px;
  border-top: 1px solid var(--border);
  color: var(--meta); font-size: 0.85em; text-align: center;
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_test_output_counts_ok_failed_ignored() {
        let stdout = "\
running 4 tests
test sip::parse::test_basic ... ok
test rtp::session::test_seq_wrap ... FAILED
test transport::udp::test_bind ... ok
test ice::stun::test_disabled ... ignored

failures:
    rtp::session::test_seq_wrap

test result: FAILED. 2 passed; 1 failed; 1 ignored; 0 measured
";
        let r = parse_test_output(stdout, "", Duration::from_secs(1));
        assert_eq!(r.total, 4);
        assert_eq!(r.passed, 2);
        assert_eq!(r.failed, 1);
        assert_eq!(r.skipped, 1);
        assert_eq!(r.tests.len(), 3); // ignored isn't kept as TestResult
        let names: Vec<&str> = r.tests.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"sip::parse::test_basic"));
        assert!(names.contains(&"rtp::session::test_seq_wrap"));
        assert!(names.contains(&"transport::udp::test_bind"));
        let failed = r.tests.iter().find(|t| !t.passed).unwrap();
        assert_eq!(failed.name, "rtp::session::test_seq_wrap");
    }

    #[test]
    fn record_non_test_cargo_failure_synthesizes_record() {
        let stdout = "test session::call::test_in_flight ... \n";
        let stderr = "thread 'main' panicked at 'boom'\nnote: run with RUST_BACKTRACE=1\n";
        let mut suite = SuiteResults {
            total: 0,
            passed: 0,
            failed: 0,
            skipped: 0,
            duration: Duration::ZERO,
            tests: Vec::new(),
        };
        record_non_test_cargo_failure(&mut suite, "exit code 101", stdout, stderr);
        assert_eq!(suite.total, 1);
        assert_eq!(suite.failed, 1);
        let synth = &suite.tests[0];
        assert_eq!(synth.name, "cargo::test::process_failure");
        assert!(!synth.passed);
        assert!(synth.output.contains("exit code 101"));
        assert!(synth.output.contains("session::call::test_in_flight"));
        assert!(synth.output.contains("panicked"));
    }

    #[test]
    fn build_report_path_increments_on_collision() {
        let tmp = std::env::temp_dir().join(format!("full_test_path_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        // Clean any leftover from previous runs
        for entry in std::fs::read_dir(&tmp).unwrap() {
            let _ = std::fs::remove_file(entry.unwrap().path());
        }

        let now = Local::now();
        let p1 = build_report_path(now, &tmp);
        std::fs::write(&p1, "x").unwrap();
        let p2 = build_report_path(now, &tmp);
        assert_ne!(p1, p2);
        assert!(p2.to_string_lossy().contains("(2)"));
        std::fs::write(&p2, "y").unwrap();
        let p3 = build_report_path(now, &tmp);
        assert!(p3.to_string_lossy().contains("(3)"));

        // cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn categorize_tests_maps_modules_correctly() {
        let mk = |n: &str, ok: bool| TestResult {
            name: n.to_string(),
            passed: ok,
            output: String::new(),
        };
        let tests = vec![
            mk("sip::parser::a", true),
            mk("transport::udp::b", true),
            mk("transaction::client::c", true),
            mk("dialog::state::d", true),
            mk("session::call::e", false),
            mk("sdp::parse::f", true),
            mk("rtp::pkt::g", true),
            mk("srtp::sdes::h", true),
            mk("ice::stun::i", true),
            mk("media::g711::j", true),
            mk("core::error::k", true),
            mk("integration_basic_calls::test_x", false),
        ];
        let cats = categorize_tests(&tests);
        let lookup: std::collections::HashMap<&str, &CategoryStats> =
            cats.iter().map(|c| (c.name.as_str(), c)).collect();
        for n in [
            "SIP",
            "Transport",
            "Transaction",
            "Dialog",
            "Session",
            "SDP",
            "RTP",
            "SRTP",
            "ICE",
            "Media",
            "Core",
            "Integration",
        ] {
            assert!(lookup.contains_key(n), "missing category {n}");
        }
        assert_eq!(lookup["Session"].failed, 1);
        assert_eq!(lookup["Integration"].failed, 1);
        // Failing categories should sort first
        assert!(cats[0].failed > 0);
    }

    #[test]
    fn parse_options_recognises_flags() {
        let o = parse_options(&[]).unwrap();
        assert!(!o.skip_quality);
        assert!(!o.skip_supply);
        assert!(!o.skip_coverage);

        let o = parse_options(&["--skip-quality".into()]).unwrap();
        assert!(o.skip_quality);

        let o = parse_options(&[
            "--skip-quality".into(),
            "--skip-supply".into(),
            "--skip-coverage".into(),
        ])
        .unwrap();
        assert!(o.skip_quality && o.skip_supply && o.skip_coverage);

        assert!(parse_options(&["--help".into()]).is_none());
        assert!(parse_options(&["-h".into()]).is_none());
        assert!(parse_options(&["--bogus".into()]).is_none());
    }

    #[test]
    fn parse_coverage_json_extracts_totals() {
        let json = r#"{
            "data": [{
                "totals": {
                    "lines":     {"count": 120, "covered": 80},
                    "functions": {"count": 10,  "covered": 7},
                    "regions":   {"count": 50,  "covered": 30},
                    "branches":  {"count": 0,   "covered": 0}
                }
            }]
        }"#;
        let m = parse_coverage_json(json, Duration::from_secs(2), false).unwrap();
        assert_eq!(m.lines_total, 120);
        assert_eq!(m.lines_covered, 80);
        assert_eq!(m.functions_total, 10);
        assert_eq!(m.functions_covered, 7);
        assert_eq!(m.regions_total, 50);
        assert_eq!(m.regions_covered, 30);
        assert!(!m.branch_enabled);
    }

    #[test]
    fn parse_coverage_json_handles_missing_keys() {
        let json = r#"{"data":[{"totals":{"lines":{"count":10,"covered":5}}}]}"#;
        let m = parse_coverage_json(json, Duration::ZERO, false).unwrap();
        assert_eq!(m.lines_covered, 5);
        assert_eq!(m.functions_total, 0);
        assert_eq!(m.regions_total, 0);
    }

    #[test]
    fn parse_coverage_json_rejects_malformed_input() {
        assert!(parse_coverage_json("not json", Duration::ZERO, false).is_none());
        assert!(parse_coverage_json("{}", Duration::ZERO, false).is_none());
    }

    #[test]
    fn parse_coverage_json_tolerates_nested_subobjects() {
        let json = r#"{
            "data": [{
                "totals": {
                    "lines": {
                        "count": 100,
                        "covered": 90,
                        "extra": {"nested": true, "foo": [1,2,3]}
                    },
                    "functions": {"count": 8, "covered": 8},
                    "regions":   {"count": 1, "covered": 1},
                    "branches":  {"count": 0, "covered": 0}
                }
            }]
        }"#;
        let m = parse_coverage_json(json, Duration::ZERO, false).unwrap();
        assert_eq!(m.lines_covered, 90);
        assert_eq!(m.lines_total, 100);
    }

    #[test]
    fn coverage_failure_marks_run_as_failed() {
        let r = CoverageResult::Failed {
            duration: Duration::from_secs(3),
            stderr_tail: "thread 'main' panicked\n".to_string(),
        };
        assert!(!r.passed());
        assert!(!r.is_skipped());

        let skipped = CoverageResult::Skipped;
        assert!(!skipped.passed());
        assert!(skipped.is_skipped());

        let ok = CoverageResult::Ok(CoverageMetrics {
            lines_covered: 1,
            lines_total: 1,
            functions_covered: 1,
            functions_total: 1,
            branches_covered: 0,
            branches_total: 0,
            regions_covered: 1,
            regions_total: 1,
            branch_enabled: false,
            duration: Duration::ZERO,
        });
        assert!(ok.passed());
        assert!(!ok.is_skipped());
    }

    #[test]
    fn coverage_failure_renders_in_html_report() {
        let now = Local::now();
        let cov = CoverageResult::Failed {
            duration: Duration::from_secs(3),
            stderr_tail: "thread 'main' panicked at 'boom'".to_string(),
        };
        let html = generate_html_report(
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&cov),
            "abc",
            now,
            "Default",
        );
        assert!(html.contains("cargo llvm-cov FAILED"));
        assert!(html.contains("status-fail"));
    }

    #[test]
    fn html_report_contains_expected_sections() {
        let now = Local::now();
        let suite = SuiteResults {
            total: 2,
            passed: 1,
            failed: 1,
            skipped: 0,
            duration: Duration::from_secs(2),
            tests: vec![
                TestResult {
                    name: "sip::a".into(),
                    passed: true,
                    output: String::new(),
                },
                TestResult {
                    name: "rtp::b".into(),
                    passed: false,
                    output: "boom".into(),
                },
            ],
        };
        let cov = CoverageResult::Ok(CoverageMetrics {
            lines_covered: 10,
            lines_total: 20,
            functions_covered: 5,
            functions_total: 10,
            branches_covered: 0,
            branches_total: 0,
            regions_covered: 4,
            regions_total: 8,
            branch_enabled: false,
            duration: Duration::from_secs(1),
        });
        let html = generate_html_report(
            None,
            None,
            None,
            None,
            Some(&suite),
            None,
            Some(&cov),
            "abc1234 (main)",
            now,
            "Default",
        );
        assert!(html.contains("rsiprtp Full Test Report"));
        assert!(html.contains("Summary"));
        assert!(html.contains("Test Breakdown by Category"));
        assert!(html.contains("Failed Tests"));
        assert!(html.contains("Coverage"));
        assert!(html.contains("rtp::b"));
    }

    #[test]
    fn markdown_report_contains_expected_sections() {
        let now = Local::now();
        let suite = SuiteResults {
            total: 1,
            passed: 1,
            failed: 0,
            skipped: 0,
            duration: Duration::from_secs(1),
            tests: vec![TestResult {
                name: "sip::a".into(),
                passed: true,
                output: String::new(),
            }],
        };
        let md = generate_markdown_report(
            None,
            None,
            None,
            None,
            Some(&suite),
            None,
            None,
            "abc",
            now,
            "Default",
        );
        assert!(md.contains("# rsiprtp Full Test Report"));
        assert!(md.contains("## Summary"));
        assert!(md.contains("Test Breakdown by Category"));
    }

    #[test]
    fn fmt_is_issue_only_matches_diff_in_lines() {
        assert!(fmt_is_issue("Diff in /path/to/foo.rs:12"));
        assert!(!fmt_is_issue("error: rustfmt failed somewhere"));
        assert!(!fmt_is_issue("warning: unused manifest key"));
        assert!(!fmt_is_issue("crates/rsiprtp-core/src/error.rs"));
        assert!(!fmt_is_issue("would reformat foo.rs"));
        assert!(!fmt_is_issue(""));
    }

    #[test]
    fn clippy_is_issue_anchors_at_line_start() {
        assert!(clippy_is_issue("warning: unused variable"));
        assert!(clippy_is_issue("error: aborting due to previous error"));
        assert!(clippy_is_issue("error[E0382]: borrow of moved value"));
        assert!(clippy_is_issue("    warning: nested clippy lint"));
        // Cargo's own "warning: unused manifest key" still starts with "warning: " so
        // it does match — the original concern was that lines containing but not
        // beginning with "warning:" (e.g. paths) should not match. Verify that:
        assert!(!clippy_is_issue("note: this warning: appears mid-line"));
        assert!(!clippy_is_issue("/path/to/error.rs:1:1"));
        assert!(!clippy_is_issue("rsiprtp-core/src/error.rs"));
        assert!(!clippy_is_issue(""));
    }

    #[test]
    fn deny_is_transient_recognises_known_signatures() {
        assert!(deny_is_transient(
            "error: failed to fetch advisory database\n"
        ));
        assert!(deny_is_transient("warning: unable to update index"));
        assert!(!deny_is_transient(
            "error[license]: license `GPL-3.0` is not allowed"
        ));
        assert!(!deny_is_transient(
            "error[advisory]: RUSTSEC-2024-0001 found"
        ));
    }

    #[test]
    fn deny_transient_failure_classified_as_skipped() {
        let stderr =
            "error: failed to fetch `https://github.com/RustSec/advisory-db.git`\n  unable to update";
        let r = classify_quality_output(
            "cargo deny",
            false,
            "",
            stderr,
            Duration::from_secs(2),
            deny_is_issue,
            Some(deny_is_transient),
        );
        assert!(r.skipped);
        assert!(r.passed); // skip is treated as pass for overall_ok
        assert_eq!(r.skip_reason.as_deref(), Some("transient"));
    }

    #[test]
    fn deny_real_violation_classified_as_failed() {
        let stderr = "error[license]: license `GPL-3.0` is not allowed for crate foo v1.0.0\n";
        let r = classify_quality_output(
            "cargo deny",
            false,
            "",
            stderr,
            Duration::from_secs(2),
            deny_is_issue,
            Some(deny_is_transient),
        );
        assert!(!r.skipped);
        assert!(!r.passed);
        assert!(!r.issues.is_empty());
    }

    #[test]
    fn categorize_tests_recognises_doc_tests() {
        let mk = |n: &str, ok: bool| TestResult {
            name: n.to_string(),
            passed: ok,
            output: String::new(),
        };
        let tests = vec![
            mk("sip::parser::a", true),
            mk("src/lib.rs - foo::Bar::baz (line 123)", true),
            mk("src/lib.rs - quux (line 7)", false),
            mk("integration_basic_calls::test_x", true),
        ];
        let cats = categorize_tests(&tests);
        let lookup: std::collections::HashMap<&str, &CategoryStats> =
            cats.iter().map(|c| (c.name.as_str(), c)).collect();
        assert!(lookup.contains_key("Doc tests"), "missing Doc tests");
        assert_eq!(lookup["Doc tests"].total, 2);
        assert_eq!(lookup["Doc tests"].passed, 1);
        assert_eq!(lookup["Doc tests"].failed, 1);
        assert!(lookup.contains_key("SIP"));
        assert!(lookup.contains_key("Integration"));
    }

    #[test]
    fn build_failure_marks_run_as_failed() {
        let r = BuildResult {
            passed: false,
            duration: Duration::from_secs(2),
            stderr_tail: "error[E0432]: unresolved import\n".to_string(),
        };
        assert!(!r.passed);

        let now = Local::now();
        let html = generate_html_report(
            None,
            None,
            None,
            Some(&r),
            None,
            None,
            None,
            "abc",
            now,
            "Default",
        );
        assert!(html.contains("cargo build"));
        assert!(html.contains("cargo build FAILED"));
        assert!(html.contains("status-fail"));
    }
}
