use clap::{Parser, ValueEnum};
use querylens::analyzer::{analyze_sql, AnalysisOptions, Dialect, StaticAnalysis};
use querylens::config::{load_config, SqlInspectConfig};
use querylens::error::AppError;
use querylens::insights::{explain_query, extract_lineage_report, extract_tables};
use querylens::prompt::{build_prompt, parse_sql_explanation, Finding, Severity, SqlExplanation};
#[cfg(feature = "bedrock")]
use querylens::providers::bedrock::BedrockProvider;
use querylens::providers::local::LocalProvider;
use querylens::providers::openai::OpenAIProvider;
use querylens::providers::LlmProvider;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

#[derive(ValueEnum, Clone, Debug)]
enum ProviderArg {
    Openai,
    #[cfg(feature = "bedrock")]
    Bedrock,
    Local,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum SeverityArg {
    Low,
    Medium,
    High,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum DialectArg {
    Generic,
    Athena,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    Lineage {
        file: PathBuf,
        #[arg(long)]
        column: Option<String>,
    },
    Risk {
        file: PathBuf,
        #[arg(long, default_value_t = false)]
        summary_only: bool,
    },
    Guard {
        file: PathBuf,
        #[arg(long, value_enum, default_value = "high")]
        max_risk: SeverityArg,
        #[arg(long)]
        deny_rule: Vec<String>,
    },
    Simulate {
        file: PathBuf,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    Tables {
        file: PathBuf,
    },
    Explain {
        file: PathBuf,
    },
    PgExplain {
        #[arg(long)]
        file: PathBuf,
    },
    PgExplainRun {
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        sql: Option<String>,
    },
    Analyze {
        dir: PathBuf,
        #[arg(long, default_value = "*.sql")]
        glob: String,
        #[arg(long, default_value_t = false)]
        changed_only: bool,
        #[arg(long)]
        changed_base: Option<String>,
        #[arg(long, default_value_t = 5)]
        top: usize,
        #[arg(long, default_value_t = false)]
        verbose: bool,
    },
    PrReview {
        #[arg(long)]
        base: String,
        #[arg(long, default_value = "HEAD")]
        head: String,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        #[arg(long, default_value = "*.sql")]
        glob: String,
        #[arg(long, default_value_t = false, conflicts_with = "markdown")]
        ci: bool,
        #[arg(long, default_value_t = false, conflicts_with = "ci")]
        markdown: bool,
        #[arg(long, default_value_t = false, conflicts_with_all = ["ci", "markdown"])]
        cost_diff: bool,
    },
}

#[derive(Parser, Debug)]
#[command(name = "querylens")]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long, value_enum, default_value = "openai")]
    provider: ProviderArg,

    #[arg(long)]
    sql: Option<String>,

    #[arg(long)]
    file: Option<PathBuf>,

    #[arg(long)]
    dir: Option<PathBuf>,

    #[arg(long, default_value = "*.sql")]
    glob: String,

    #[arg(long, value_enum, global = true)]
    dialect: Option<DialectArg>,

    #[arg(long)]
    config: Option<PathBuf>,

    #[arg(long)]
    static_only: bool,

    #[arg(long, value_enum)]
    fail_on: Option<SeverityArg>,

    #[arg(long, global = true)]
    json: bool,

    #[arg(long, global = true, conflicts_with = "scan_tb")]
    scan_bytes: Option<u64>,

    #[arg(long, global = true, conflicts_with = "scan_bytes")]
    scan_tb: Option<f64>,

    #[arg(
        long,
        global = true,
        help = "Use a past Athena QueryExecutionId to pull DataScannedInBytes (post-run calibration; requires AWS creds/CLI)"
    )]
    athena_query_execution_id: Option<String>,

    #[arg(long, global = true, help = "AWS region for Athena lookup (optional)")]
    athena_region: Option<String>,

    #[arg(long, global = true)]
    stats_file: Option<PathBuf>,
}

#[derive(Debug)]
enum InputMode {
    Sql(String),
    File(PathBuf, String),
    Dir(PathBuf),
}

#[derive(Debug, serde::Serialize)]
struct FileReport {
    path: String,
    summary: String,
    estimated_cost_impact: String,
    findings: Vec<Finding>,
    suggestions: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
struct RiskReport {
    file: String,
    risk_score: String,
    reasons: Vec<String>,
    estimated_scan: String,
}

#[derive(Debug, serde::Serialize)]
struct RepoSummary {
    analyzed_files: usize,
    high_files: usize,
    medium_files: usize,
    low_files: usize,
    full_table_scan_files: usize,
    multi_join_files: usize,
    cartesian_files: usize,
    top_files: Vec<RepoTopFile>,
}

#[derive(Debug, serde::Serialize)]
struct RepoTopFile {
    path: String,
    risk: String,
    rules: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
struct RepoVerboseFile {
    path: String,
    risk: String,
    findings: Vec<String>,
    reason: String,
}

#[derive(Debug, serde::Serialize)]
struct PrReviewSummary {
    status: String,
    changed_sql_files: usize,
    new_high_risk_queries: usize,
    partition_filter_regressions: usize,
    order_by_without_limit_regressions: usize,
    possible_join_amplification_regressions: usize,
    scan_cost_increase_files: usize,
}

#[derive(Debug, serde::Serialize)]
struct PrFileDelta {
    path: String,
    previous_risk: String,
    current_risk: String,
    risk_trend: String,
    new_issues: Vec<String>,
    resolved_issues: Vec<String>,
    persistent_risk_factors: Vec<String>,
    estimated_scan_from: String,
    estimated_scan_to: String,
    scan_delta: String,
    cost_regression: Option<String>,
    cost_regression_reason: Option<String>,
    cost_recommendation: Option<String>,
    scan_increase_factor: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct PrReviewReport {
    base: String,
    head: String,
    summary: PrReviewSummary,
    files: Vec<PrFileDelta>,
}

#[derive(Debug, serde::Serialize)]
struct GuardReport {
    policy: String,
    status: String,
    risk: String,
    blocking_violations: Vec<String>,
    why_blocked: Option<String>,
}

#[derive(Debug, Default, serde::Serialize)]
struct PgBuffers {
    shared_hit: u64,
    shared_read: u64,
    shared_dirtied: u64,
    shared_written: u64,
    temp_read: u64,
    temp_written: u64,
}

#[derive(Debug, serde::Serialize)]
struct PgExplainSummary {
    planning_time_ms: Option<f64>,
    execution_time_ms: Option<f64>,
    total_rows: Option<f64>,
    seq_scans: Vec<String>,
    buffers: Option<PgBuffers>,
    warnings: Vec<String>,
}

fn env(name: &'static str) -> Result<String, AppError> {
    std::env::var(name).map_err(|_| AppError::MissingEnv(name))
}

fn read_input(args: &Args) -> anyhow::Result<InputMode> {
    match (&args.sql, &args.file, &args.dir) {
        (Some(s), None, None) => Ok(InputMode::Sql(s.clone())),
        (None, Some(p), None) => Ok(InputMode::File(p.clone(), std::fs::read_to_string(p)?)),
        (None, None, Some(dir)) => Ok(InputMode::Dir(dir.clone())),
        _ => Err(anyhow::anyhow!(
            "Provide exactly one of --sql, --file, or --dir"
        )),
    }
}

fn to_severity(arg: SeverityArg) -> Severity {
    match arg {
        SeverityArg::Low => Severity::Low,
        SeverityArg::Medium => Severity::Medium,
        SeverityArg::High => Severity::High,
    }
}

fn parse_severity_name(value: &str) -> Option<Severity> {
    match value {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        _ => None,
    }
}

fn config_fail_on(config: &SqlInspectConfig) -> Option<Severity> {
    config.fail_on.as_deref().and_then(parse_severity_name)
}

fn analysis_options(config: &SqlInspectConfig) -> AnalysisOptions {
    AnalysisOptions {
        suggest_limit_for_exploratory: config.suggest_limit_for_exploratory.unwrap_or(true),
        dialect: match config.dialect.as_deref() {
            Some("athena") => Dialect::Athena,
            _ => Dialect::Generic,
        },
    }
}

fn cli_dialect(arg: DialectArg) -> Dialect {
    match arg {
        DialectArg::Generic => Dialect::Generic,
        DialectArg::Athena => Dialect::Athena,
    }
}

fn build_static_explanation(analysis: &StaticAnalysis) -> SqlExplanation {
    let summary = if analysis.findings.is_empty() {
        "Static analysis found no obvious anti-patterns.".to_string()
    } else {
        format!(
            "Static analysis found {} structured finding(s).",
            analysis.findings.len()
        )
    };

    SqlExplanation {
        summary,
        tables: vec![],
        joins: vec![],
        filters: vec![],
        risks: analysis.risks.clone(),
        suggestions: analysis.suggestions.clone(),
        anti_patterns: analysis.anti_patterns.clone(),
        findings: analysis.findings.clone(),
        estimated_cost_impact: analysis.estimated_cost_impact.clone(),
        confidence: if analysis.findings.is_empty() {
            "high".to_string()
        } else {
            "medium".to_string()
        },
    }
}

fn push_unique(values: &mut Vec<String>, new_items: &[String]) {
    for item in new_items {
        if !values.iter().any(|existing| existing == item) {
            values.push(item.clone());
        }
    }
}

fn push_unique_findings(values: &mut Vec<Finding>, new_items: &[Finding]) {
    for item in new_items {
        if !values.iter().any(|existing| {
            existing.rule_id == item.rule_id
                && existing.message == item.message
                && existing.evidence == item.evidence
        }) {
            values.push(item.clone());
        }
    }
}

fn merge_static_analysis(parsed: &mut SqlExplanation, analysis: &StaticAnalysis) {
    push_unique(&mut parsed.anti_patterns, &analysis.anti_patterns);
    push_unique(&mut parsed.risks, &analysis.risks);
    push_unique(&mut parsed.suggestions, &analysis.suggestions);
    push_unique_findings(&mut parsed.findings, &analysis.findings);

    if parsed.estimated_cost_impact == "unknown"
        || cost_rank(&analysis.estimated_cost_impact) > cost_rank(&parsed.estimated_cost_impact)
    {
        parsed.estimated_cost_impact = analysis.estimated_cost_impact.clone();
    }

    if parsed.confidence == "unknown" && !analysis.findings.is_empty() {
        parsed.confidence = "medium".to_string();
    }
}

fn extract_suppressed_rules(sql: &str) -> HashSet<String> {
    let mut suppressed = HashSet::new();
    for line in sql.lines() {
        let lower = line.to_ascii_lowercase();
        let Some(idx) = lower.find("querylens: disable=") else {
            continue;
        };
        let raw = &line[idx + "querylens: disable=".len()..];
        let raw = raw
            .split("*/")
            .next()
            .unwrap_or(raw)
            .split("--")
            .next()
            .unwrap_or(raw);
        for part in raw.split(',') {
            let token = part
                .trim()
                .trim_matches(|c: char| c == '*' || c == '/' || c == ';')
                .to_ascii_uppercase();
            if !token.is_empty() {
                suppressed.insert(token);
            }
        }
    }
    suppressed
}

fn apply_inline_suppressions_to_analysis(analysis: &mut StaticAnalysis, sql: &str) {
    let suppressed = extract_suppressed_rules(sql);
    if suppressed.is_empty() {
        return;
    }
    let mut removed_messages = Vec::new();
    analysis.findings.retain(|f| {
        let keep = !suppressed.contains(&f.rule_id.to_ascii_uppercase());
        if !keep {
            removed_messages.push(f.message.clone());
        }
        keep
    });
    for message in removed_messages {
        analysis.anti_patterns.retain(|item| item != &message);
    }
}

fn apply_rule_controls(parsed: &mut SqlExplanation, config: &SqlInspectConfig) {
    let Some(rules) = config.rules.as_ref() else {
        return;
    };

    let mut disabled_messages = Vec::new();
    parsed.findings.retain(|finding| {
        let Some(control) = rules.get(&finding.rule_id) else {
            return true;
        };
        if control.enabled == Some(false) {
            disabled_messages.push(finding.message.clone());
            return false;
        }
        true
    });

    for finding in &mut parsed.findings {
        if let Some(control) = rules.get(&finding.rule_id) {
            if let Some(severity_name) = control.severity.as_deref() {
                if let Some(severity) = parse_severity_name(severity_name) {
                    finding.severity = severity;
                }
            }
        }
    }

    for message in disabled_messages {
        parsed.anti_patterns.retain(|item| item != &message);
    }

    recalculate_cost_impact(parsed);
}

fn cost_rank(value: &str) -> u8 {
    match value {
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        _ => 0,
    }
}

fn severity_label(value: &Severity) -> &'static str {
    match value {
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Unknown => "UNKNOWN",
    }
}

fn recalculate_cost_impact(parsed: &mut SqlExplanation) {
    let max_rank = parsed
        .findings
        .iter()
        .map(|f| f.severity.rank())
        .max()
        .unwrap_or(0);

    parsed.estimated_cost_impact = match max_rank {
        0 => "low",
        1 => "low",
        2 => "medium",
        _ => "high",
    }
    .to_string();
}

fn render_explanation(parsed: &SqlExplanation) -> String {
    let mut out = String::new();

    out.push_str("\nSummary:\n");
    out.push_str(&parsed.summary);
    out.push_str("\n\n");

    out.push_str("Estimated Cost Impact: ");
    out.push_str(&parsed.estimated_cost_impact);
    out.push('\n');

    out.push_str("Confidence: ");
    out.push_str(&parsed.confidence);
    out.push('\n');

    if !parsed.tables.is_empty() {
        out.push_str("\nTables: ");
        out.push_str(&parsed.tables.join(", "));
        out.push('\n');
    }
    if !parsed.findings.is_empty() {
        out.push_str("\nFindings:\n");
        for finding in &parsed.findings {
            out.push_str(" - [");
            out.push_str(severity_label(&finding.severity));
            out.push_str("] ");
            out.push_str(&finding.rule_id);
            out.push_str(": ");
            out.push_str(&finding.message);
            out.push('\n');
            out.push_str("   Why: ");
            out.push_str(&finding.why_it_matters);
            out.push('\n');
            if !finding.evidence.is_empty() {
                out.push_str("   Evidence: ");
                out.push_str(&finding.evidence.join(", "));
                out.push('\n');
            }
        }
    } else if !parsed.anti_patterns.is_empty() {
        out.push_str("\nAnti-Patterns:\n");
        for item in &parsed.anti_patterns {
            out.push_str(" - ");
            out.push_str(item);
            out.push('\n');
        }
    }
    if !parsed.joins.is_empty() {
        out.push_str("\nJoins:\n");
        for j in &parsed.joins {
            out.push_str(" - ");
            out.push_str(j);
            out.push('\n');
        }
    }
    if !parsed.filters.is_empty() {
        out.push_str("\nFilters:\n");
        for f in &parsed.filters {
            out.push_str(" - ");
            out.push_str(f);
            out.push('\n');
        }
    }
    if !parsed.risks.is_empty() {
        out.push_str("\nRisks:\n");
        for r in &parsed.risks {
            out.push_str(" - ");
            out.push_str(r);
            out.push('\n');
        }
    }
    if !parsed.suggestions.is_empty() {
        out.push_str("\nSuggestions:\n");
        for s in &parsed.suggestions {
            out.push_str(" - ");
            out.push_str(s);
            out.push('\n');
        }
    }

    out
}

fn render_scan_report(results: &[FileReport]) -> String {
    let mut out = String::new();
    out.push_str(&format!("\nScanned {} SQL file(s)\n", results.len()));
    for result in results {
        out.push('\n');
        out.push_str(&result.path);
        out.push('\n');
        out.push_str("  Estimated Cost Impact: ");
        out.push_str(&result.estimated_cost_impact);
        out.push('\n');
        for finding in &result.findings {
            out.push_str("  - [");
            out.push_str(severity_label(&finding.severity));
            out.push_str("] ");
            out.push_str(&finding.rule_id);
            out.push_str(": ");
            out.push_str(&finding.message);
            out.push('\n');
        }
    }
    out
}

fn max_finding_severity(findings: &[Finding]) -> Severity {
    findings
        .iter()
        .map(|finding| finding.severity.clone())
        .max_by_key(Severity::rank)
        .unwrap_or(Severity::Unknown)
}

fn should_fail(findings: &[Finding], threshold: Option<Severity>) -> bool {
    match threshold {
        Some(threshold) => max_finding_severity(findings).rank() >= threshold.rank(),
        None => false,
    }
}

async fn build_provider(args: &Args) -> Result<Box<dyn LlmProvider>, anyhow::Error> {
    match args.provider {
        ProviderArg::Openai => {
            let key = env("OPENAI_API_KEY")?;
            let model =
                std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4.1-mini".to_string());
            Ok(Box::new(OpenAIProvider::new(key, model)))
        }
        #[cfg(feature = "bedrock")]
        ProviderArg::Bedrock => {
            let model_id = env("BEDROCK_MODEL_ID")?;
            let provider = BedrockProvider::new(model_id).await?;
            Ok(Box::new(provider))
        }
        ProviderArg::Local => {
            let model = env("LOCAL_LLM_MODEL")?;
            let base_url = std::env::var("LOCAL_LLM_BASE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
            let api_key = std::env::var("LOCAL_LLM_API_KEY").ok();
            Ok(Box::new(LocalProvider::new(base_url, model, api_key)))
        }
    }
}

async fn analyze_single_sql(
    sql: &str,
    static_only: bool,
    args: &Args,
    options: AnalysisOptions,
) -> anyhow::Result<SqlExplanation> {
    let mut analysis = analyze_sql(sql, options);
    apply_inline_suppressions_to_analysis(&mut analysis, sql);

    if static_only {
        return Ok(build_static_explanation(&analysis));
    }

    let prompt = build_prompt(sql);
    let provider = build_provider(args).await?;
    let raw_json = provider.explain_sql_json(&prompt).await?;
    let mut parsed = parse_sql_explanation(&raw_json)?;
    merge_static_analysis(&mut parsed, &analysis);
    Ok(parsed)
}

fn collect_sql_files(root: &Path, pattern: &str) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_sql_files_recursive(root, pattern, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_changed_sql_files(root: &Path, pattern: &str) -> anyhow::Result<Vec<PathBuf>> {
    let tracked_worktree = ProcessCommand::new("git")
        .arg("diff")
        .arg("--name-only")
        .arg("--diff-filter=ACMRTUXB")
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run git diff for changed-only mode: {e}"))?;

    if !tracked_worktree.status.success() {
        return Err(anyhow::anyhow!(
            "git diff failed for changed-only mode: {}",
            String::from_utf8_lossy(&tracked_worktree.stderr).trim()
        ));
    }

    let tracked_staged = ProcessCommand::new("git")
        .arg("diff")
        .arg("--cached")
        .arg("--name-only")
        .arg("--diff-filter=ACMRTUXB")
        .output()
        .map_err(|e| {
            anyhow::anyhow!("failed to run git diff --cached for changed-only mode: {e}")
        })?;

    if !tracked_staged.status.success() {
        return Err(anyhow::anyhow!(
            "git diff --cached failed for changed-only mode: {}",
            String::from_utf8_lossy(&tracked_staged.stderr).trim()
        ));
    }

    let untracked = ProcessCommand::new("git")
        .arg("ls-files")
        .arg("--others")
        .arg("--exclude-standard")
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run git ls-files for changed-only mode: {e}"))?;

    if !untracked.status.success() {
        return Err(anyhow::anyhow!(
            "git ls-files failed for changed-only mode: {}",
            String::from_utf8_lossy(&untracked.stderr).trim()
        ));
    }

    let mut files = Vec::new();
    let cwd = std::env::current_dir()?;
    let root_abs = if root.is_absolute() {
        root.to_path_buf()
    } else {
        cwd.join(root)
    };
    for output in [
        &tracked_worktree.stdout,
        &tracked_staged.stdout,
        &untracked.stdout,
    ] {
        for line in String::from_utf8_lossy(output).lines() {
            let candidate = cwd.join(line);
            if !candidate.starts_with(&root_abs) {
                continue;
            }
            if candidate.is_file() && matches_pattern(&candidate, pattern) {
                files.push(candidate);
            }
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn collect_changed_sql_files_between_refs(
    root: &Path,
    pattern: &str,
    base: &str,
    head: &str,
) -> anyhow::Result<Vec<PathBuf>> {
    let output = ProcessCommand::new("git")
        .arg("diff")
        .arg("--name-only")
        .arg("--diff-filter=ACMRTUXB")
        .arg(format!("{base}..{head}"))
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run git diff for pr-review mode: {e}"))?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "git diff failed for pr-review mode: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let cwd = std::env::current_dir()?;
    let root_abs = if root.is_absolute() {
        root.to_path_buf()
    } else {
        cwd.join(root)
    };

    let mut files = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let candidate = cwd.join(line);
        if !candidate.starts_with(&root_abs) {
            continue;
        }
        if candidate.is_file() && matches_pattern(&candidate, pattern) {
            files.push(candidate);
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn read_file_at_ref(path: &Path, git_ref: &str) -> anyhow::Result<Option<String>> {
    let cwd = std::env::current_dir()?;
    let rel = path
        .strip_prefix(&cwd)
        .map_err(|_| anyhow::anyhow!("path {} is outside repository cwd", path.display()))?;
    let rel_s = rel.to_string_lossy().replace('\\', "/");

    let output = ProcessCommand::new("git")
        .arg("show")
        .arg(format!("{git_ref}:{rel_s}"))
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run git show for {git_ref}:{rel_s}: {e}"))?;

    if output.status.success() {
        return Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()));
    }

    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if stderr.contains("does not exist")
        || stderr.contains("exists on disk, but not in")
        || stderr.contains("pathspec")
        || stderr.contains("fatal: invalid object name")
    {
        return Ok(None);
    }

    Err(anyhow::anyhow!(
        "git show failed for {git_ref}:{rel_s}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn collect_sql_files_recursive(
    root: &Path,
    pattern: &str,
    files: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(name.as_ref(), ".git" | "target" | ".idea") {
                continue;
            }
            collect_sql_files_recursive(&path, pattern, files)?;
        } else if file_type.is_file() && matches_pattern(&path, pattern) {
            files.push(path);
        }
    }

    Ok(())
}

fn matches_pattern(path: &Path, pattern: &str) -> bool {
    let file_name = match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => name,
        None => return false,
    };

    if pattern == "*.sql" {
        return path.extension().and_then(|ext| ext.to_str()) == Some("sql");
    }

    if let Some(suffix) = pattern.strip_prefix('*') {
        return file_name.ends_with(suffix);
    }

    file_name == pattern
}

fn read_sql_file(path: &Path) -> anyhow::Result<String> {
    Ok(std::fs::read_to_string(path)?)
}

fn render_lineage(path: &Path, sql: &str, column: Option<&str>) -> String {
    let report = extract_lineage_report(sql);
    let mut out = String::new();
    out.push_str(&format!("{}\n", path.display()));

    let projections = if let Some(column) = column {
        report
            .projections
            .into_iter()
            .filter(|item| item.output.eq_ignore_ascii_case(column))
            .collect::<Vec<_>>()
    } else {
        report.projections
    };

    out.push_str("Projections:\n");
    if projections.is_empty() {
        if let Some(column) = column {
            out.push_str("No lineage found for column: ");
            out.push_str(column);
            out.push('\n');
        } else {
            out.push_str("none\n");
        }
    } else {
        for item in projections {
            out.push_str(&item.output);
            out.push('\n');
            out.push_str(" └─ ");
            out.push_str(&item.expression);
            out.push('\n');
        }
    }

    if !report.filters.is_empty() {
        out.push_str("Filters:\n");
        for filter in report.filters {
            out.push_str(" └─ ");
            out.push_str(&filter);
            out.push('\n');
        }
    }

    if !report.joins.is_empty() {
        out.push_str("Joins:\n");
        for join in report.joins {
            out.push_str(" └─ ");
            out.push_str(&join);
            out.push('\n');
        }
    }
    out
}

fn render_tables(sql: &str) -> String {
    let tables = extract_tables(sql);
    let mut out = String::new();
    out.push_str("Tables used:\n");
    for table in tables {
        out.push_str("- ");
        out.push_str(&table);
        out.push('\n');
    }
    out
}

fn render_query_explanation(sql: &str) -> String {
    let explanation = explain_query(sql);
    let mut out = String::new();
    out.push_str("Query explanation\n");
    out.push_str("Meaning: ");
    out.push_str(&explanation.meaning);
    out.push('\n');

    out.push_str("Tables: ");
    if explanation.tables.is_empty() {
        out.push_str("unknown");
    } else {
        out.push_str(&explanation.tables.join(", "));
    }
    out.push('\n');

    out.push_str("Join: ");
    if explanation.joins.is_empty() {
        out.push_str("none");
    } else {
        out.push_str(&explanation.joins.join("; "));
    }
    out.push('\n');

    out.push_str("Aggregation: ");
    if explanation.aggregation_details.is_empty() {
        out.push_str("none");
    } else {
        out.push_str(&explanation.aggregation_details.join(", "));
    }
    out.push('\n');
    out
}

fn risk_score(findings: &[Finding]) -> &'static str {
    match max_finding_severity(findings) {
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Unknown => "LOW",
    }
}

fn risk_impact_note(reasons: &[String]) -> String {
    let mut note = String::new();
    let joined = reasons.join(" ").to_ascii_lowercase();
    if joined.contains("full table scan") || joined.contains("missing where") {
        note = "Likely full table scan without selective filter".to_string();
    } else if joined.contains("cartesian") || joined.contains("cross join") {
        note = "Possible join explosion (row amplification)".to_string();
    } else if joined.contains("select *") {
        note = "Wide result set may increase scan and network cost".to_string();
    }
    note
}

fn estimated_scan_label(args: &Args, sql: Option<&str>) -> anyhow::Result<String> {
    if let Some(tb) = args.scan_tb {
        return Ok(format!("{tb:.2} TB"));
    }
    if let Some(bytes) = args.scan_bytes {
        let tb = bytes as f64 / 1_000_000_000_000_f64;
        return Ok(format!("{tb:.2} TB"));
    }
    if let Some(bytes) = fetch_athena_scanned_bytes(args)? {
        let tb = bytes as f64 / 1_000_000_000_000_f64;
        return Ok(format!("{tb:.2} TB"));
    }
    if let Some(bytes) = estimate_scan_from_stats_file(args, sql)? {
        let tb = bytes as f64 / 1_000_000_000_000_f64;
        return Ok(format!("{tb:.2} TB"));
    }
    Ok("unknown".to_string())
}

fn fetch_athena_scanned_bytes(args: &Args) -> anyhow::Result<Option<u64>> {
    let Some(execution_id) = args.athena_query_execution_id.as_deref() else {
        return Ok(None);
    };

    let mut cmd = ProcessCommand::new("aws");
    cmd.arg("athena")
        .arg("get-query-execution")
        .arg("--query-execution-id")
        .arg(execution_id)
        .arg("--output")
        .arg("json");

    if let Some(region) = args.athena_region.as_deref() {
        cmd.arg("--region").arg(region);
    }

    let output = cmd
        .output()
        .map_err(|e| anyhow::anyhow!("failed to execute aws cli for Athena lookup: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "aws athena get-query-execution failed for {}: {}",
            execution_id,
            stderr.trim()
        ));
    }

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|e| {
        anyhow::anyhow!("failed to parse Athena get-query-execution output as JSON: {e}")
    })?;

    let scanned = value["QueryExecution"]["Statistics"]["DataScannedInBytes"]
        .as_u64()
        .or_else(|| {
            value["QueryExecution"]["Statistics"]["DataScannedInBytes"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
        });

    Ok(scanned)
}

fn estimate_scan_from_stats_file(args: &Args, sql: Option<&str>) -> anyhow::Result<Option<u64>> {
    let (Some(path), Some(sql)) = (args.stats_file.as_ref(), sql) else {
        return Ok(None);
    };

    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read stats file {}: {e}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
        anyhow::anyhow!("failed to parse stats file {} as JSON: {e}", path.display())
    })?;

    let tables = extract_tables(sql);
    if tables.is_empty() {
        return Ok(None);
    }

    let mut total = 0_u64;
    let mut matched = false;
    let filters = extract_lineage_report(sql).filters;

    for table in tables {
        if let Some(stats) = parse_table_stats(&value, &table) {
            if let Some(bytes) = stats.total_bytes {
                let fraction = estimate_scan_fraction(&stats, &filters);
                total = total.saturating_add((bytes as f64 * fraction) as u64);
                matched = true;
                continue;
            }
        }

        // Fallback: accept bare bytes at top-level for the table
        if let Some(bytes) = parse_bytes_value(
            value
                .get("tables")
                .and_then(|v| v.get(&table))
                .unwrap_or_else(|| value.get(&table).unwrap_or(&serde_json::Value::Null)),
        ) {
            let fraction = if filters.is_empty() { 1.0 } else { 0.7 };
            total = total.saturating_add((bytes as f64 * fraction) as u64);
            matched = true;
        }
    }

    if matched {
        Ok(Some(total))
    } else {
        Ok(None)
    }
}

#[derive(Default)]
struct TableStats {
    total_bytes: Option<u64>,
    row_count: Option<u64>,
    partition_columns: Vec<String>,
    partitions_per_year: Option<u32>,
}

fn parse_table_stats(root: &serde_json::Value, table: &str) -> Option<TableStats> {
    let node = root
        .get("tables")
        .and_then(|v| v.get(table))
        .or_else(|| root.get(table))?;

    let mut stats = TableStats::default();
    stats.total_bytes = parse_bytes_value(node.get("total_bytes").unwrap_or(node));
    stats.row_count = node
        .get("row_count")
        .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()));
    stats.partition_columns = node
        .get("partition_columns")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                .collect()
        })
        .unwrap_or_default();
    stats.partitions_per_year = node
        .get("partitions_per_year")
        .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()))
        .map(|n| n as u32);

    if stats.total_bytes.is_none()
        && stats.row_count.is_none()
        && stats.partition_columns.is_empty()
    {
        None
    } else {
        Some(stats)
    }
}

fn parse_bytes_value(value: &serde_json::Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    if let Some(s) = value.as_str() {
        return s.parse::<u64>().ok();
    }
    value.get("bytes").and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
    })
}

fn estimate_scan_fraction(stats: &TableStats, filters: &[String]) -> f64 {
    if stats.partition_columns.is_empty() {
        return if filters.is_empty() { 1.0 } else { 0.7 };
    }

    let filters_lower: Vec<String> = filters.iter().map(|f| f.to_ascii_lowercase()).collect();
    let mut matches_partition = false;
    for part in &stats.partition_columns {
        if filters_lower.iter().any(|f| f.contains(part)) {
            matches_partition = true;
            break;
        }
    }

    if matches_partition {
        // If we see an obvious range, assume a small slice; otherwise even smaller.
        let has_range = filters_lower
            .iter()
            .any(|f| f.contains("between") || f.contains(">") || f.contains("<"));
        if let Some(parts) = stats.partitions_per_year {
            // crude: assume daily partitions
            let days = if has_range { 30.0 } else { 1.0 };
            return (days / parts.max(1) as f64).clamp(0.01, 1.0);
        }
        return if has_range { 0.05 } else { 0.02 };
    }

    if filters.is_empty() {
        1.0
    } else {
        0.7
    }
}

fn guard_block_reasons(
    findings: &[Finding],
    max_risk: Severity,
    deny_rules: &[String],
) -> Vec<String> {
    let mut reasons = Vec::new();
    let worst = max_finding_severity(findings);
    if worst.rank() > max_risk.rank() && max_risk != Severity::Unknown {
        reasons.push(format!(
            "maximum risk threshold exceeded (worst={}, threshold={})",
            severity_label(&worst),
            severity_label(&max_risk)
        ));
    }

    let deny_rules_upper: HashSet<String> =
        deny_rules.iter().map(|r| r.to_ascii_uppercase()).collect();
    for finding in findings {
        if deny_rules_upper.contains(&finding.rule_id.to_ascii_uppercase()) {
            reasons.push(format!(
                "deny-rule matched {} ({})",
                finding.rule_id, finding.message
            ));
        }
    }

    reasons
}

fn simulate_query(sql: &str, limit: usize) -> String {
    let trimmed = sql.trim().trim_end_matches(';').trim();
    let normalized = strip_sql_comments(trimmed).to_ascii_lowercase();
    let tokens: Vec<&str> = normalized.split_whitespace().collect();
    if has_limit_clause(&tokens) {
        return format!("{trimmed};");
    }

    if normalized.starts_with("select ") || normalized.starts_with("with ") {
        return format!("{trimmed}\nLIMIT {limit};");
    }

    format!("SELECT *\nFROM (\n{trimmed}\n) AS querylens_preview\nLIMIT {limit};")
}

fn strip_sql_comments(sql: &str) -> String {
    let mut out = String::new();
    let mut chars = sql.chars().peekable();
    let mut in_line_comment = false;
    let mut in_block_comment = false;

    while let Some(c) = chars.next() {
        if in_line_comment {
            if c == '\n' {
                in_line_comment = false;
                out.push('\n');
            }
            continue;
        }
        if in_block_comment {
            if c == '*' && matches!(chars.peek(), Some('/')) {
                chars.next();
                in_block_comment = false;
            }
            continue;
        }
        if c == '-' && matches!(chars.peek(), Some('-')) {
            chars.next();
            in_line_comment = true;
            continue;
        }
        if c == '/' && matches!(chars.peek(), Some('*')) {
            chars.next();
            in_block_comment = true;
            continue;
        }
        out.push(c);
    }

    out
}

fn has_limit_clause(tokens: &[&str]) -> bool {
    for (idx, token) in tokens.iter().enumerate() {
        if *token != "limit" {
            continue;
        }
        if let Some(next) = tokens.get(idx + 1) {
            let next = next.trim_matches(|c: char| c == ',' || c == ';' || c == ')');
            if next == "all"
                || next == "?"
                || next.starts_with(':')
                || next.starts_with('$')
                || next.chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                return true;
            }
        }
    }
    false
}

fn build_effective_static_explanation(
    sql: &str,
    options: AnalysisOptions,
    config: &SqlInspectConfig,
) -> SqlExplanation {
    let mut analysis = analyze_sql(sql, options);
    apply_inline_suppressions_to_analysis(&mut analysis, sql);
    let mut parsed = build_static_explanation(&analysis);
    apply_rule_controls(&mut parsed, config);
    parsed
}

fn build_risk_report(path: &Path, findings: &[Finding], estimated_scan: String) -> RiskReport {
    let mut reasons = Vec::new();
    for finding in findings {
        reasons.push(format!(
            "{}: {}",
            finding.rule_id.replace('_', " ").to_lowercase(),
            finding.message
        ));
    }

    if reasons.is_empty() {
        reasons.push("No high-confidence anti-patterns detected by static rules".to_string());
    }

    RiskReport {
        file: path.display().to_string(),
        risk_score: risk_score(findings).to_string(),
        reasons,
        estimated_scan,
    }
}

fn render_risk_report(report: &RiskReport) -> String {
    let mut out = String::new();
    out.push_str(&report.file);
    out.push('\n');
    out.push_str("Risk score: ");
    out.push_str(&report.risk_score);
    out.push_str("\n\nReasons:\n");
    for reason in &report.reasons {
        out.push_str("- ");
        out.push_str(reason);
        out.push('\n');
    }
    let impact = risk_impact_note(&report.reasons);
    if !impact.is_empty() {
        out.push('\n');
        out.push_str("Impact: ");
        out.push_str(&impact);
        out.push('\n');
    }
    out.push_str("\nEstimated scan: ");
    out.push_str(&report.estimated_scan);
    out.push('\n');
    out
}

fn render_risk_summary(report: &RiskReport) -> String {
    let mut out = String::new();
    out.push_str("SQL Inspect Risk\n");
    out.push_str("File: ");
    out.push_str(&report.file);
    out.push('\n');
    out.push_str("Risk: ");
    out.push_str(&report.risk_score);
    out.push('\n');
    out.push_str("Estimated scan: ");
    out.push_str(&report.estimated_scan);
    out.push('\n');
    let impact = risk_impact_note(&report.reasons);
    if !impact.is_empty() {
        out.push_str("Impact: ");
        out.push_str(&impact);
        out.push('\n');
    }
    out.push_str("Top reasons:\n");
    for reason in report.reasons.iter().take(3) {
        out.push_str("- ");
        out.push_str(reason);
        out.push('\n');
    }
    out
}

fn render_folder_summary_with_verbose(
    summary: &RepoSummary,
    counts: &std::collections::BTreeMap<String, usize>,
    verbose_files: &[RepoVerboseFile],
) -> String {
    let mut out = String::new();
    out.push_str("SQL Inspect Report\n");
    out.push_str("Scope: current selection\n");
    out.push('\n');
    out.push_str(&format!("Analyzed {} SQL files\n", summary.analyzed_files));
    out.push('\n');
    out.push_str("Top risks:\n");
    out.push_str(&format!("1. {} HIGH-risk files\n", summary.high_files));
    out.push_str(&format!(
        "2. {} files likely scan full tables\n",
        summary.full_table_scan_files
    ));
    out.push_str(&format!(
        "3. {} files have complex multi-join patterns\n",
        summary.multi_join_files
    ));
    out.push_str(&format!(
        "4. {} files contain CROSS JOIN or likely Cartesian behavior\n",
        summary.cartesian_files
    ));
    out.push('\n');
    out.push_str("Severity shape:\n");
    out.push_str(&format!("HIGH: {} files\n", summary.high_files));
    out.push_str(&format!("MEDIUM: {} files\n", summary.medium_files));
    out.push_str(&format!("LOW: {} files\n", summary.low_files));
    out.push('\n');
    out.push_str("Most severe files:\n");
    if summary.top_files.is_empty() {
        out.push_str("- none\n");
    } else {
        for item in &summary.top_files {
            out.push_str("- ");
            out.push_str(&item.path);
            out.push_str("  ");
            out.push_str(&item.risk);
            if !item.rules.is_empty() {
                out.push_str("  ");
                out.push_str(&item.rules.join(", "));
            }
            out.push('\n');
        }
    }
    out.push('\n');
    out.push_str("Warnings:\n");
    if counts.is_empty() {
        out.push_str("- none\n");
    } else {
        for (rule, count) in counts {
            out.push_str(&format!("- {} {}\n", count, rule));
        }
    }

    if !verbose_files.is_empty() {
        out.push('\n');
        for file in verbose_files {
            out.push_str("File: ");
            out.push_str(&file.path);
            out.push('\n');
            out.push_str("Risk: ");
            out.push_str(&file.risk);
            out.push('\n');
            out.push_str("Findings:\n");
            for finding in &file.findings {
                out.push_str("- ");
                out.push_str(finding);
                out.push('\n');
            }
            out.push_str("Reason:\n");
            out.push_str(&file.reason);
            out.push('\n');
            out.push('\n');
        }
    }

    out
}

fn bytes_to_tb_label(bytes: Option<u64>) -> String {
    match bytes {
        Some(bytes) => format!("{:.2} TB", bytes as f64 / 1_000_000_000_000_f64),
        None => "unknown".to_string(),
    }
}

fn bytes_to_human_label(bytes: Option<u64>) -> String {
    match bytes {
        Some(bytes) if bytes >= 1_000_000_000_000 => {
            format!("{:.2} TB", bytes as f64 / 1_000_000_000_000_f64)
        }
        Some(bytes) if bytes >= 1_000_000_000 => {
            format!("{:.0} GB", bytes as f64 / 1_000_000_000_f64)
        }
        Some(bytes) if bytes >= 1_000_000 => {
            format!("{:.0} MB", bytes as f64 / 1_000_000_f64)
        }
        Some(bytes) => format!("{bytes} B"),
        None => "unknown".to_string(),
    }
}

fn estimate_scan_bytes(args: &Args, sql: &str) -> anyhow::Result<Option<u64>> {
    if let Some(tb) = args.scan_tb {
        return Ok(Some((tb * 1_000_000_000_000_f64) as u64));
    }
    if let Some(bytes) = args.scan_bytes {
        return Ok(Some(bytes));
    }
    estimate_scan_from_stats_file(args, Some(sql))
}

fn has_rule(findings: &[Finding], rule_id: &str) -> bool {
    findings.iter().any(|f| f.rule_id == rule_id)
}

fn risk_trend_label(prev: Severity, curr: Severity) -> &'static str {
    if curr.rank() > prev.rank() {
        "regressed"
    } else if curr.rank() < prev.rank() {
        "improved"
    } else {
        "unchanged"
    }
}

fn scan_delta_label(from: Option<u64>, to: Option<u64>) -> String {
    match (from, to) {
        (Some(from), Some(to)) if to > from => {
            format!("+{:.2} TB", (to - from) as f64 / 1_000_000_000_000_f64)
        }
        (Some(from), Some(to)) if to < from => {
            format!("-{:.2} TB", (from - to) as f64 / 1_000_000_000_000_f64)
        }
        (Some(_), Some(_)) => "0.00 TB".to_string(),
        _ => "unknown".to_string(),
    }
}

fn scan_increase_factor_label(from: Option<u64>, to: Option<u64>) -> Option<String> {
    match (from, to) {
        (Some(from), Some(to)) if from > 0 && to > from => {
            Some(format!("{:.1}x", to as f64 / from as f64))
        }
        _ => None,
    }
}

fn cost_regression_level(from: Option<u64>, to: Option<u64>) -> Option<String> {
    let factor = match (from, to) {
        (Some(from), Some(to)) if from > 0 && to > from => to as f64 / from as f64,
        _ => return None,
    };

    let level = if factor >= 10.0 {
        "HIGH"
    } else if factor >= 3.0 {
        "MEDIUM"
    } else {
        "LOW"
    };

    Some(level.to_string())
}

fn first_filter(sql: &str) -> Option<String> {
    extract_lineage_report(sql).filters.into_iter().next()
}

fn derive_cost_regression_reason(
    prev_sql: Option<&str>,
    curr_sql: &str,
    prev_findings: &[Finding],
    curr_findings: &[Finding],
) -> (Option<String>, Option<String>) {
    let prev_filter = prev_sql.and_then(first_filter);
    let curr_filter = first_filter(curr_sql);

    if prev_filter.is_some() && curr_filter.is_none() {
        let removed = prev_filter.unwrap_or_default();
        return (
            Some(format!("Filter removed: {removed}")),
            Some("Restore a selective WHERE or partition predicate.".to_string()),
        );
    }

    if !has_rule(prev_findings, "ATHENA_MISSING_PARTITION_FILTER")
        && has_rule(curr_findings, "ATHENA_MISSING_PARTITION_FILTER")
    {
        let table = extract_tables(curr_sql)
            .into_iter()
            .next()
            .unwrap_or_else(|| "query".to_string());
        return (
            Some(format!("Partition filter removed or missing on {table}")),
            Some("Restore a partition predicate on the scanned table.".to_string()),
        );
    }

    if !has_rule(prev_findings, "FULL_TABLE_SCAN_LIKELY")
        && has_rule(curr_findings, "FULL_TABLE_SCAN_LIKELY")
    {
        return (
            Some("Query is now likely to scan the full table.".to_string()),
            Some("Reintroduce narrowing filters before scanning the base table.".to_string()),
        );
    }

    (None, None)
}

fn render_pr_review(report: &PrReviewReport) -> String {
    let mut out = String::new();
    out.push_str("SQL Inspect PR Review\n");
    out.push_str("Base: ");
    out.push_str(&report.base);
    out.push('\n');
    out.push_str("Head: ");
    out.push_str(&report.head);
    out.push_str("\n\n");
    out.push_str("PR status: ");
    out.push_str(&report.summary.status);
    out.push_str("\n\n");
    if report.summary.status == "PASS" {
        out.push_str("No new SQL risk regressions detected.\n\n");
    }
    out.push_str(&format!(
        "{} changed SQL files\n",
        report.summary.changed_sql_files
    ));
    out.push_str(&format!(
        "{} new HIGH-risk queries\n",
        report.summary.new_high_risk_queries
    ));
    out.push_str(&format!(
        "{} query lost partition filter\n",
        report.summary.partition_filter_regressions
    ));
    out.push_str(&format!(
        "{} ORDER BY without LIMIT regressions\n",
        report.summary.order_by_without_limit_regressions
    ));
    out.push_str(&format!(
        "{} possible join amplification regressions\n",
        report.summary.possible_join_amplification_regressions
    ));
    out.push_str(&format!(
        "{} files increased estimated scan cost\n",
        report.summary.scan_cost_increase_files
    ));

    for file in &report.files {
        out.push('\n');
        out.push_str("File: ");
        out.push_str(&file.path);
        out.push('\n');
        out.push_str("Previous risk: ");
        out.push_str(&file.previous_risk);
        out.push('\n');
        out.push_str("Current risk: ");
        out.push_str(&file.current_risk);
        out.push('\n');
        out.push_str("Risk trend: ");
        out.push_str(&file.risk_trend);
        out.push('\n');

        if !file.new_issues.is_empty() {
            out.push_str("New issues:\n");
            for issue in &file.new_issues {
                out.push_str("- ");
                out.push_str(issue);
                out.push('\n');
            }
        }
        if !file.resolved_issues.is_empty() {
            out.push_str("Resolved:\n");
            for issue in &file.resolved_issues {
                out.push_str("- ");
                out.push_str(issue);
                out.push('\n');
            }
        }
        if !file.persistent_risk_factors.is_empty() {
            out.push_str("Still risky because:\n");
            for issue in &file.persistent_risk_factors {
                out.push_str("- ");
                out.push_str(issue);
                out.push('\n');
            }
        }
        out.push_str("Estimated scan: ");
        out.push_str(&file.estimated_scan_from);
        out.push_str(" -> ");
        out.push_str(&file.estimated_scan_to);
        out.push('\n');
        out.push_str("Estimated scan delta: ");
        out.push_str(&file.scan_delta);
        out.push('\n');
    }
    out
}

fn render_pr_review_ci(report: &PrReviewReport) -> String {
    let mut out = String::new();
    out.push_str("PR status: ");
    out.push_str(&report.summary.status);
    out.push('\n');
    out.push_str(&format!(
        "Changed SQL files: {}\n",
        report.summary.changed_sql_files
    ));
    out.push_str(&format!(
        "New HIGH-risk queries: {}\n",
        report.summary.new_high_risk_queries
    ));
    out.push_str(&format!(
        "Partition filter regressions: {}\n",
        report.summary.partition_filter_regressions
    ));
    out.push_str(&format!(
        "ORDER BY without LIMIT regressions: {}\n",
        report.summary.order_by_without_limit_regressions
    ));
    out.push_str(&format!(
        "Join amplification regressions: {}\n",
        report.summary.possible_join_amplification_regressions
    ));
    out.push_str(&format!(
        "Files with higher estimated scan: {}\n",
        report.summary.scan_cost_increase_files
    ));
    out
}

fn render_pr_review_markdown(report: &PrReviewReport) -> String {
    let mut out = String::new();
    out.push_str("# SQL Inspect PR Review\n\n");
    out.push_str("## Summary\n\n");
    out.push_str("- **Base:** `");
    out.push_str(&report.base);
    out.push_str("`\n");
    out.push_str("- **Head:** `");
    out.push_str(&report.head);
    out.push_str("`\n");
    out.push_str("- **PR status:** **");
    out.push_str(&report.summary.status);
    out.push_str("**\n");
    out.push_str("- **Changed SQL files:** ");
    out.push_str(&report.summary.changed_sql_files.to_string());
    out.push('\n');
    out.push_str("- **New HIGH-risk queries:** ");
    out.push_str(&report.summary.new_high_risk_queries.to_string());
    out.push('\n');
    out.push_str("- **Partition filter regressions:** ");
    out.push_str(&report.summary.partition_filter_regressions.to_string());
    out.push('\n');
    out.push_str("- **ORDER BY without LIMIT regressions:** ");
    out.push_str(
        &report
            .summary
            .order_by_without_limit_regressions
            .to_string(),
    );
    out.push('\n');
    out.push_str("- **Join amplification regressions:** ");
    out.push_str(
        &report
            .summary
            .possible_join_amplification_regressions
            .to_string(),
    );
    out.push('\n');
    out.push_str("- **Files with higher estimated scan:** ");
    out.push_str(&report.summary.scan_cost_increase_files.to_string());
    out.push_str("\n\n");

    out.push_str("## Result\n\n");
    if report.summary.status == "PASS" {
        out.push_str("No new SQL risk regressions detected.\n\n");
    } else {
        out.push_str("This PR introduces new SQL risk regressions.\n\n");
    }

    if report.files.is_empty() {
        return out;
    }

    out.push_str("## File Review\n\n");
    for file in &report.files {
        out.push_str("### `");
        out.push_str(&file.path);
        out.push_str("`\n\n");
        out.push_str("- **Risk:** ");
        out.push_str(&file.previous_risk);
        out.push_str(" -> ");
        out.push_str(&file.current_risk);
        out.push_str(" (`");
        out.push_str(&file.risk_trend);
        out.push_str("`)\n");
        out.push_str("- **Estimated scan:** ");
        out.push_str(&file.estimated_scan_from);
        out.push_str(" -> ");
        out.push_str(&file.estimated_scan_to);
        out.push_str(" (`");
        out.push_str(&file.scan_delta);
        out.push_str("`)\n");

        if !file.new_issues.is_empty() {
            out.push_str("- **New findings:** ");
            out.push_str(&file.new_issues.join(", "));
            out.push('\n');
        }
        if !file.resolved_issues.is_empty() {
            out.push_str("- **Resolved:** ");
            out.push_str(&file.resolved_issues.join(", "));
            out.push('\n');
        }
        if !file.persistent_risk_factors.is_empty() {
            out.push_str("- **Still risky because:** ");
            out.push_str(&file.persistent_risk_factors.join(", "));
            out.push('\n');
        }
        if file.new_issues.is_empty()
            && file.resolved_issues.is_empty()
            && file.persistent_risk_factors.is_empty()
        {
            out.push_str("- **Notes:** no rule-level changes detected\n");
        }

        out.push('\n');
    }

    out
}

fn render_pr_review_cost_diff(report: &PrReviewReport) -> String {
    let mut out = String::new();
    out.push_str("SQL Cost Regression\n\n");
    out.push_str(&format!(
        "{} changed SQL files\n",
        report.summary.changed_sql_files
    ));

    let mut any = false;
    for file in &report.files {
        if file.cost_regression.is_none() && file.scan_increase_factor.is_none() {
            continue;
        }

        any = true;
        out.push('\n');
        out.push_str("File: ");
        out.push_str(&file.path);
        out.push_str("\n\n");
        out.push_str("Estimated scan change:\n");
        out.push_str("Before: ");
        out.push_str(&file.estimated_scan_from);
        out.push('\n');
        out.push_str("After: ");
        out.push_str(&file.estimated_scan_to);
        out.push('\n');
        if let Some(factor) = &file.scan_increase_factor {
            out.push_str("Increase: ");
            out.push_str(factor);
            out.push('\n');
        }
        if let Some(level) = &file.cost_regression {
            out.push('\n');
            out.push_str("Cost regression: ");
            out.push_str(level);
            out.push('\n');
        }
        if let Some(reason) = &file.cost_regression_reason {
            out.push('\n');
            out.push_str("Reason:\n");
            out.push_str(reason);
            out.push('\n');
        }
        if let Some(recommendation) = &file.cost_recommendation {
            out.push('\n');
            out.push_str("Recommendation:\n");
            out.push_str(recommendation);
            out.push('\n');
        }
    }

    if !any {
        out.push_str("\nNo scan cost regressions detected.\n");
    }

    out
}

fn render_guard_report(report: &GuardReport) -> String {
    let mut out = String::new();
    out.push_str("SQL Inspect Guard\n");
    out.push_str("Policy: ");
    out.push_str(&report.policy);
    out.push_str("\n\n");
    out.push_str("Status: ");
    out.push_str(&report.status);
    out.push('\n');
    out.push_str("Risk: ");
    out.push_str(&report.risk);
    out.push_str("\n\n");

    if report.blocking_violations.is_empty() {
        out.push_str("No blocking violations found.\n");
    } else {
        out.push_str("Blocking violations\n");
        for rule in &report.blocking_violations {
            out.push_str("- ");
            out.push_str(rule);
            out.push('\n');
        }
        if let Some(reason) = &report.why_blocked {
            out.push('\n');
            out.push_str("Why blocked\n");
            out.push_str(reason);
            out.push('\n');
        }
        out.push('\n');
        out.push_str("Exit code: 2\n");
    }

    out
}

fn render_pg_explain(summary: &PgExplainSummary) -> String {
    let mut out = String::new();
    out.push_str("PG Explain Analysis\n");
    out.push_str("\nExecution time: ");
    out.push_str(
        &summary
            .execution_time_ms
            .map(|t| format!("{t:.2} ms"))
            .unwrap_or_else(|| "unknown".to_string()),
    );
    out.push_str("\nPlanning time: ");
    out.push_str(
        &summary
            .planning_time_ms
            .map(|t| format!("{t:.2} ms"))
            .unwrap_or_else(|| "unknown".to_string()),
    );
    out.push('\n');

    out.push_str("Rows: ");
    out.push_str(
        &summary
            .total_rows
            .map(|r| format!("{r:.0}"))
            .unwrap_or_else(|| "unknown".to_string()),
    );
    out.push('\n');

    out.push_str("Seq scans: ");
    if summary.seq_scans.is_empty() {
        out.push_str("none");
    } else {
        out.push_str(&summary.seq_scans.join(", "));
    }
    out.push('\n');

    if let Some(buf) = &summary.buffers {
        out.push_str("Buffers:\n");
        out.push_str(&format!(
            "  shared hit/read/dirtied/written: {}/{}/{}/{}\n",
            buf.shared_hit, buf.shared_read, buf.shared_dirtied, buf.shared_written
        ));
        out.push_str(&format!(
            "  temp read/written: {}/{}\n",
            buf.temp_read, buf.temp_written
        ));
    }

    if !summary.warnings.is_empty() {
        out.push_str("\nWarnings:\n");
        for w in &summary.warnings {
            out.push_str("- ");
            out.push_str(w);
            out.push('\n');
        }
    }

    out
}

fn parse_pg_explain_summary(input: &str) -> anyhow::Result<PgExplainSummary> {
    let value: serde_json::Value = serde_json::from_str(input)
        .map_err(|e| anyhow::anyhow!("failed to parse EXPLAIN JSON: {e}"))?;

    let root = if let Some(arr) = value.as_array() {
        arr.first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("EXPLAIN JSON array is empty"))?
    } else {
        value
    };

    let plan = root
        .get("Plan")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("EXPLAIN JSON missing Plan key"))?;

    let planning_time_ms = root.get("Planning Time").and_then(|v| v.as_f64());
    let execution_time_ms = root.get("Execution Time").and_then(|v| v.as_f64());

    let mut seq_scans = Vec::new();
    let mut warnings = Vec::new();
    let mut buffers = PgBuffers::default();
    let mut total_rows_acc = 0.0_f64;

    walk_pg_plan(
        &plan,
        &mut seq_scans,
        &mut total_rows_acc,
        &mut buffers,
        &mut warnings,
    );

    let buffers_present = buffers.shared_hit
        + buffers.shared_read
        + buffers.shared_dirtied
        + buffers.shared_written
        + buffers.temp_read
        + buffers.temp_written
        > 0;

    Ok(PgExplainSummary {
        planning_time_ms,
        execution_time_ms,
        total_rows: if total_rows_acc > 0.0 {
            Some(total_rows_acc)
        } else {
            None
        },
        seq_scans,
        buffers: if buffers_present { Some(buffers) } else { None },
        warnings,
    })
}

fn walk_pg_plan(
    plan: &serde_json::Value,
    seq_scans: &mut Vec<String>,
    total_rows: &mut f64,
    buffers: &mut PgBuffers,
    warnings: &mut Vec<String>,
) {
    let node_type = plan
        .get("Node Type")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    let relation = plan
        .get("Relation Name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let alias = plan.get("Alias").and_then(|v| v.as_str()).unwrap_or("");

    let loops = plan
        .get("Actual Loops")
        .and_then(|v| v.as_f64())
        .unwrap_or(1.0);
    if let Some(rows) = plan.get("Actual Rows").and_then(|v| v.as_f64()) {
        *total_rows += rows * loops;
    }

    accumulate_buffers(plan, buffers);

    if node_type == "Seq Scan" {
        let label = if !relation.is_empty() {
            relation.to_string()
        } else if !alias.is_empty() {
            alias.to_string()
        } else {
            "Seq Scan".to_string()
        };
        seq_scans.push(label.clone());
        if plan.get("Filter").is_none() {
            warnings.push(format!("Seq Scan on {label} without filter"));
        }
    }

    if let Some(children) = plan.get("Plans").and_then(|v| v.as_array()) {
        for child in children {
            walk_pg_plan(child, seq_scans, total_rows, buffers, warnings);
        }
    }
}

fn accumulate_buffers(plan: &serde_json::Value, buffers: &mut PgBuffers) {
    buffers.shared_hit += plan
        .get("Shared Hit Blocks")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    buffers.shared_read += plan
        .get("Shared Read Blocks")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    buffers.shared_dirtied += plan
        .get("Shared Dirtied Blocks")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    buffers.shared_written += plan
        .get("Shared Written Blocks")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    buffers.temp_read += plan
        .get("Temp Read Blocks")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    buffers.temp_written += plan
        .get("Temp Written Blocks")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
}

fn run_pg_explain_via_psql(sql: &str) -> anyhow::Result<PgExplainSummary> {
    // Require DATABASE_URL or standard PG envs to be set
    let db_url = std::env::var("DATABASE_URL").ok();
    let has_url = db_url.is_some();
    let has_pg_host = std::env::var("PGHOST").is_ok();
    if !has_url && !has_pg_host {
        return Err(anyhow::anyhow!(
            "Set DATABASE_URL or PGHOST/PGUSER/PGDATABASE env vars for pg-explain-run"
        ));
    }

    let explain_sql = format!("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {sql}");
    let mut cmd = ProcessCommand::new("psql");
    if let Some(url) = db_url {
        cmd.arg("-d").arg(url);
    }
    let output = cmd
        .arg("-X")
        .arg("-q")
        .arg("-t")
        .arg("-A")
        .arg("-c")
        .arg(&explain_sql)
        .output()
        .map_err(|e| anyhow::anyhow!("failed to execute psql: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("psql failed: {}", stderr.trim()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Err(anyhow::anyhow!("psql returned empty EXPLAIN output"));
    }

    parse_pg_explain_summary(&stdout)
}

fn validate_not_templated_sql(sql: &str) -> anyhow::Result<()> {
    if sql.contains("{{") || sql.contains("{%") {
        return Err(anyhow::anyhow!(
            "Templated SQL detected (Jinja/dbt). Provide compiled SQL for pg-explain-run (e.g., dbt compile -> target/compiled/...sql)."
        ));
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    let config = load_config(args.config.as_deref())?;

    if let Some(command) = &args.command {
        match command {
            Commands::Lineage { file, column } => {
                let sql = read_sql_file(file)?;
                print!("{}", render_lineage(file, &sql, column.as_deref()));
                return Ok(());
            }
            Commands::Risk { file, summary_only } => {
                let sql = read_sql_file(file)?;
                let mut options = analysis_options(&config);
                if let Some(dialect) = args.dialect {
                    options.dialect = cli_dialect(dialect);
                }
                let parsed = build_effective_static_explanation(&sql, options, &config);
                let report = build_risk_report(
                    file,
                    &parsed.findings,
                    estimated_scan_label(&args, Some(&sql))?,
                );
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else if *summary_only {
                    print!("{}", render_risk_summary(&report));
                } else {
                    print!("{}", render_risk_report(&report));
                }
                return Ok(());
            }
            Commands::Guard {
                file,
                max_risk,
                deny_rule,
            } => {
                let sql = read_sql_file(file)?;
                let mut options = analysis_options(&config);
                if let Some(dialect) = args.dialect {
                    options.dialect = cli_dialect(dialect);
                }
                let parsed = build_effective_static_explanation(&sql, options, &config);
                let block_reasons =
                    guard_block_reasons(&parsed.findings, to_severity(*max_risk), deny_rule);
                let mut blocking_violations = parsed
                    .findings
                    .iter()
                    .filter(|f| f.severity.rank() >= to_severity(*max_risk).rank())
                    .map(|f| f.rule_id.clone())
                    .collect::<Vec<_>>();
                for reason in &block_reasons {
                    if let Some(rest) = reason.strip_prefix("deny-rule matched ") {
                        if let Some(rule) = rest.split_whitespace().next() {
                            if !blocking_violations.iter().any(|r| r == rule) {
                                blocking_violations.push(rule.to_string());
                            }
                        }
                    }
                }
                blocking_violations.sort();
                blocking_violations.dedup();
                let report = GuardReport {
                    policy: "default".to_string(),
                    status: if blocking_violations.is_empty() {
                        "PASS".to_string()
                    } else {
                        "FAIL".to_string()
                    },
                    risk: risk_score(&parsed.findings).to_string(),
                    blocking_violations,
                    why_blocked: if block_reasons.is_empty()
                        && parsed
                            .findings
                            .iter()
                            .all(|f| f.severity.rank() < to_severity(*max_risk).rank())
                    {
                        None
                    } else {
                        parsed
                            .findings
                            .iter()
                            .max_by_key(|f| f.severity.rank())
                            .map(|f| f.why_it_matters.clone())
                    },
                };

                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "file": file.display().to_string(),
                            "blocked": report.status == "FAIL",
                            "risk_score": risk_score(&parsed.findings),
                            "reasons": block_reasons,
                            "findings": parsed.findings,
                            "guard": report
                        }))?
                    );
                } else {
                    print!("{}", render_guard_report(&report));
                }

                if report.status == "FAIL" {
                    std::process::exit(2);
                }
                return Ok(());
            }
            Commands::Simulate { file, limit } => {
                let sql = read_sql_file(file)?;
                let simulated = simulate_query(&sql, *limit);
                println!("{simulated}");
                return Ok(());
            }
            Commands::Tables { file } => {
                let sql = read_sql_file(file)?;
                print!("{}", render_tables(&sql));
                return Ok(());
            }
            Commands::Explain { file } => {
                let sql = read_sql_file(file)?;
                print!("{}", render_query_explanation(&sql));
                return Ok(());
            }
            Commands::PgExplain { file } => {
                let raw = std::fs::read_to_string(file)
                    .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", file.display()))?;
                let summary = parse_pg_explain_summary(&raw)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                } else {
                    print!("{}", render_pg_explain(&summary));
                }
                return Ok(());
            }
            Commands::PgExplainRun { file, sql } => {
                let sql_text = if let Some(path) = file {
                    std::fs::read_to_string(path)
                        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?
                } else if let Some(sql) = sql {
                    sql.clone()
                } else {
                    return Err(anyhow::anyhow!(
                        "Provide --file <sql.sql> or --sql \"...\" for pg-explain-run"
                    ));
                };

                validate_not_templated_sql(&sql_text)?;

                eprintln!(
                    "Executing EXPLAIN (ANALYZE, BUFFERS) via psql; query will run on the database."
                );
                let summary = run_pg_explain_via_psql(&sql_text)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                } else {
                    print!("{}", render_pg_explain(&summary));
                }
                return Ok(());
            }
            Commands::Analyze {
                dir,
                glob,
                changed_only,
                changed_base,
                top,
                verbose,
            } => {
                let mut options = analysis_options(&config);
                if let Some(dialect) = args.dialect {
                    options.dialect = cli_dialect(dialect);
                }
                let files = if *changed_only {
                    if let Some(base) = changed_base {
                        collect_changed_sql_files_between_refs(dir, glob, base, "HEAD")?
                    } else {
                        collect_changed_sql_files(dir, glob)?
                    }
                } else {
                    collect_sql_files(dir, glob)?
                };
                let mut counts = std::collections::BTreeMap::<String, usize>::new();
                let mut high_files = 0usize;
                let mut medium_files = 0usize;
                let mut low_files = 0usize;
                let mut full_scan_files = 0usize;
                let mut multi_join_files = 0usize;
                let mut cartesian_files = 0usize;
                let mut offenders = Vec::<(PathBuf, Severity, Vec<String>)>::new();
                let mut verbose_files = Vec::<RepoVerboseFile>::new();

                for file in &files {
                    let sql = std::fs::read_to_string(file)?;
                    let parsed = build_effective_static_explanation(&sql, options, &config);
                    for finding in &parsed.findings {
                        *counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
                    }
                    let risk = max_finding_severity(&parsed.findings);
                    match risk {
                        Severity::High => high_files += 1,
                        Severity::Medium => medium_files += 1,
                        _ => low_files += 1,
                    }
                    if has_rule(&parsed.findings, "FULL_TABLE_SCAN_LIKELY") {
                        full_scan_files += 1;
                    }
                    if has_rule(&parsed.findings, "MULTIPLE_JOINS")
                        || has_rule(&parsed.findings, "WIDE_JOIN_GRAPH")
                    {
                        multi_join_files += 1;
                    }
                    if has_rule(&parsed.findings, "CROSS_JOIN")
                        || has_rule(&parsed.findings, "POSSIBLE_CARTESIAN_JOIN")
                    {
                        cartesian_files += 1;
                    }
                    let rules = parsed
                        .findings
                        .iter()
                        .map(|f| f.rule_id.clone())
                        .collect::<Vec<_>>();
                    offenders.push((file.clone(), risk.clone(), rules));
                    if *verbose {
                        let reason = parsed
                            .findings
                            .iter()
                            .max_by_key(|f| f.severity.rank())
                            .map(|f| f.why_it_matters.clone())
                            .unwrap_or_else(|| "No obvious anti-patterns detected".to_string());
                        verbose_files.push(RepoVerboseFile {
                            path: file.display().to_string(),
                            risk: severity_label(&risk).to_string(),
                            findings: parsed.findings.iter().map(|f| f.rule_id.clone()).collect(),
                            reason,
                        });
                    }
                }

                offenders.sort_by(|a, b| {
                    b.1.rank()
                        .cmp(&a.1.rank())
                        .then_with(|| b.2.len().cmp(&a.2.len()))
                });
                let top_files = offenders
                    .into_iter()
                    .take(*top)
                    .map(|(path, risk, rules)| RepoTopFile {
                        path: path.display().to_string(),
                        risk: severity_label(&risk).to_string(),
                        rules,
                    })
                    .collect::<Vec<_>>();
                let summary = RepoSummary {
                    analyzed_files: files.len(),
                    high_files,
                    medium_files,
                    low_files,
                    full_table_scan_files: full_scan_files,
                    multi_join_files,
                    cartesian_files,
                    top_files,
                };

                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "summary": summary,
                            "warnings": counts,
                            "verbose_files": verbose_files
                        }))?
                    );
                } else {
                    print!(
                        "{}",
                        render_folder_summary_with_verbose(&summary, &counts, &verbose_files)
                    );
                }
                return Ok(());
            }
            Commands::PrReview {
                base,
                head,
                dir,
                glob,
                ci,
                markdown,
                cost_diff,
            } => {
                let mut options = analysis_options(&config);
                if let Some(dialect) = args.dialect {
                    options.dialect = cli_dialect(dialect);
                }
                let files = collect_changed_sql_files_between_refs(dir, glob, base, head)?;
                let mut reports = Vec::new();
                let mut summary = PrReviewSummary {
                    status: "PASS".to_string(),
                    changed_sql_files: files.len(),
                    new_high_risk_queries: 0,
                    partition_filter_regressions: 0,
                    order_by_without_limit_regressions: 0,
                    possible_join_amplification_regressions: 0,
                    scan_cost_increase_files: 0,
                };

                for file in files {
                    let prev_sql = read_file_at_ref(&file, base)?;
                    let curr_sql = read_file_at_ref(&file, head)?;
                    let Some(curr_sql) = curr_sql else {
                        continue;
                    };

                    let prev = prev_sql
                        .as_deref()
                        .map(|sql| build_effective_static_explanation(sql, options, &config));
                    let curr = build_effective_static_explanation(&curr_sql, options, &config);

                    let prev_findings = prev
                        .as_ref()
                        .map(|p| &p.findings)
                        .cloned()
                        .unwrap_or_default();
                    let curr_findings = curr.findings.clone();

                    let prev_rules: HashSet<String> =
                        prev_findings.iter().map(|f| f.rule_id.clone()).collect();
                    let curr_rules: HashSet<String> =
                        curr_findings.iter().map(|f| f.rule_id.clone()).collect();

                    let new_rules = curr_rules
                        .difference(&prev_rules)
                        .cloned()
                        .collect::<Vec<_>>();
                    let resolved_rules = prev_rules
                        .difference(&curr_rules)
                        .cloned()
                        .collect::<Vec<_>>();
                    let persistent_rules = curr_rules
                        .intersection(&prev_rules)
                        .cloned()
                        .collect::<Vec<_>>();

                    let prev_risk = max_finding_severity(&prev_findings);
                    let curr_risk = max_finding_severity(&curr_findings);
                    if curr_risk == Severity::High && prev_risk != Severity::High {
                        summary.new_high_risk_queries += 1;
                    }
                    if !has_rule(&prev_findings, "ATHENA_MISSING_PARTITION_FILTER")
                        && has_rule(&curr_findings, "ATHENA_MISSING_PARTITION_FILTER")
                    {
                        summary.partition_filter_regressions += 1;
                    }
                    if !has_rule(&prev_findings, "ATHENA_ORDER_BY_WITHOUT_LIMIT")
                        && has_rule(&curr_findings, "ATHENA_ORDER_BY_WITHOUT_LIMIT")
                    {
                        summary.order_by_without_limit_regressions += 1;
                    }
                    if !has_rule(&prev_findings, "POSSIBLE_CARTESIAN_JOIN")
                        && has_rule(&curr_findings, "POSSIBLE_CARTESIAN_JOIN")
                    {
                        summary.possible_join_amplification_regressions += 1;
                    }

                    let from_scan = prev_sql
                        .as_deref()
                        .map(|sql| estimate_scan_bytes(&args, sql))
                        .transpose()?
                        .flatten();
                    let to_scan = estimate_scan_bytes(&args, &curr_sql)?;
                    if let (Some(from), Some(to)) = (from_scan, to_scan) {
                        if to > from {
                            summary.scan_cost_increase_files += 1;
                        }
                    }
                    let (cost_regression_reason, cost_recommendation) =
                        derive_cost_regression_reason(
                            prev_sql.as_deref(),
                            &curr_sql,
                            &prev_findings,
                            &curr_findings,
                        );

                    reports.push(PrFileDelta {
                        path: file.display().to_string(),
                        previous_risk: severity_label(&prev_risk).to_string(),
                        current_risk: severity_label(&curr_risk).to_string(),
                        risk_trend: risk_trend_label(prev_risk, curr_risk).to_string(),
                        new_issues: new_rules,
                        resolved_issues: resolved_rules,
                        persistent_risk_factors: persistent_rules,
                        estimated_scan_from: if *cost_diff {
                            bytes_to_human_label(from_scan)
                        } else {
                            bytes_to_tb_label(from_scan)
                        },
                        estimated_scan_to: if *cost_diff {
                            bytes_to_human_label(to_scan)
                        } else {
                            bytes_to_tb_label(to_scan)
                        },
                        scan_delta: scan_delta_label(from_scan, to_scan),
                        cost_regression: cost_regression_level(from_scan, to_scan),
                        cost_regression_reason,
                        cost_recommendation,
                        scan_increase_factor: scan_increase_factor_label(from_scan, to_scan),
                    });
                }

                reports.sort_by(|a, b| {
                    let a_rank = match a.current_risk.as_str() {
                        "HIGH" => 3,
                        "MEDIUM" => 2,
                        "LOW" => 1,
                        _ => 0,
                    };
                    let b_rank = match b.current_risk.as_str() {
                        "HIGH" => 3,
                        "MEDIUM" => 2,
                        "LOW" => 1,
                        _ => 0,
                    };
                    b_rank
                        .cmp(&a_rank)
                        .then_with(|| b.new_issues.len().cmp(&a.new_issues.len()))
                });

                let failed = summary.new_high_risk_queries > 0
                    || summary.partition_filter_regressions > 0
                    || summary.order_by_without_limit_regressions > 0
                    || summary.possible_join_amplification_regressions > 0;
                if failed {
                    summary.status = "FAIL".to_string();
                }

                let report = PrReviewReport {
                    base: base.clone(),
                    head: head.clone(),
                    summary,
                    files: reports,
                };
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else if *ci {
                    print!("{}", render_pr_review_ci(&report));
                } else if *markdown {
                    print!("{}", render_pr_review_markdown(&report));
                } else if *cost_diff {
                    print!("{}", render_pr_review_cost_diff(&report));
                } else {
                    print!("{}", render_pr_review(&report));
                }
                if failed {
                    std::process::exit(1);
                }
                return Ok(());
            }
        }
    }

    let input = match read_input(&args) {
        Ok(input) => input,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let threshold = args
        .fail_on
        .map(to_severity)
        .or_else(|| config_fail_on(&config));
    let mut options = analysis_options(&config);
    if let Some(dialect) = args.dialect {
        options.dialect = cli_dialect(dialect);
    }
    let static_only = args.static_only
        || config.static_only.unwrap_or(false)
        || matches!(input, InputMode::Dir(_));

    match input {
        InputMode::Sql(sql) => {
            let mut parsed = analyze_single_sql(&sql, static_only, &args, options).await?;
            apply_rule_controls(&mut parsed, &config);
            if args.json {
                println!("{}", serde_json::to_string_pretty(&parsed)?);
            } else {
                print!("{}", render_explanation(&parsed));
            }

            if should_fail(&parsed.findings, threshold) {
                std::process::exit(1);
            }
        }
        InputMode::File(path, sql) => {
            let mut parsed = analyze_single_sql(&sql, static_only, &args, options).await?;
            apply_rule_controls(&mut parsed, &config);
            if parsed.summary == "Static analysis found no obvious anti-patterns." {
                parsed.summary = format!("Static analysis for {}", path.display());
            }

            if args.json {
                println!("{}", serde_json::to_string_pretty(&parsed)?);
            } else {
                print!("{}", render_explanation(&parsed));
            }

            if should_fail(&parsed.findings, threshold) {
                std::process::exit(1);
            }
        }
        InputMode::Dir(dir) => {
            let pattern = config.glob.as_deref().unwrap_or(&args.glob);
            let files = collect_sql_files(&dir, pattern)?;
            let mut reports = Vec::new();
            let mut should_exit = false;

            for file in files {
                let sql = std::fs::read_to_string(&file)?;
                let mut parsed = analyze_single_sql(&sql, true, &args, options).await?;
                apply_rule_controls(&mut parsed, &config);
                should_exit |= should_fail(&parsed.findings, threshold.clone());
                reports.push(FileReport {
                    path: file.display().to_string(),
                    summary: parsed.summary,
                    estimated_cost_impact: parsed.estimated_cost_impact,
                    findings: parsed.findings,
                    suggestions: parsed.suggestions,
                });
            }

            if args.json {
                println!("{}", serde_json::to_string_pretty(&reports)?);
            } else {
                print!("{}", render_scan_report(&reports));
            }

            if should_exit {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        apply_inline_suppressions_to_analysis, apply_rule_controls, collect_sql_files,
        extract_suppressed_rules, guard_block_reasons, matches_pattern, merge_static_analysis,
        parse_pg_explain_summary, read_input, render_explanation, render_guard_report,
        render_lineage, render_pg_explain, render_pr_review, render_pr_review_ci,
        render_pr_review_cost_diff, render_pr_review_markdown, render_query_explanation,
        render_risk_summary, render_tables, risk_score, should_fail, simulate_query, Args,
        Commands, DialectArg, GuardReport, InputMode, PrFileDelta, PrReviewReport, PrReviewSummary,
        ProviderArg, SeverityArg,
    };
    use clap::Parser;
    use querylens::analyzer::{analyze_sql, AnalysisOptions};
    use querylens::config::{RuleControl, SqlInspectConfig};
    use querylens::prompt::{Finding, Severity, SqlExplanation};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    #[test]
    fn args_parse_inline_sql() {
        let args =
            Args::try_parse_from(["querylens", "--sql", "select 1"]).expect("args should parse");

        assert!(matches!(args.provider, ProviderArg::Openai));
        assert_eq!(args.sql.as_deref(), Some("select 1"));
        assert!(args.command.is_none());
        assert!(args.file.is_none());
        assert!(!args.json);
    }

    #[test]
    fn args_parse_tables_subcommand() {
        let args = Args::try_parse_from(["querylens", "tables", "examples/query.sql"])
            .expect("subcommand args should parse");
        assert!(matches!(args.command, Some(Commands::Tables { .. })));
    }

    #[test]
    fn args_parse_risk_subcommand() {
        let args = Args::try_parse_from(["querylens", "risk", "examples/query.sql"])
            .expect("subcommand args should parse");
        assert!(matches!(args.command, Some(Commands::Risk { .. })));
    }

    #[test]
    fn args_parse_risk_summary_only() {
        let args =
            Args::try_parse_from(["querylens", "risk", "examples/query.sql", "--summary-only"])
                .expect("risk summary-only args should parse");
        assert!(matches!(
            args.command,
            Some(Commands::Risk {
                summary_only: true,
                ..
            })
        ));
    }

    #[test]
    fn args_parse_guard_subcommand() {
        let args = Args::try_parse_from([
            "querylens",
            "guard",
            "examples/query.sql",
            "--max-risk",
            "medium",
            "--deny-rule",
            "CROSS_JOIN",
        ])
        .expect("guard args should parse");
        assert!(matches!(args.command, Some(Commands::Guard { .. })));
    }

    #[test]
    fn args_parse_simulate_subcommand() {
        let args = Args::try_parse_from([
            "querylens",
            "simulate",
            "examples/query.sql",
            "--limit",
            "50",
        ])
        .expect("simulate args should parse");
        assert!(matches!(args.command, Some(Commands::Simulate { .. })));
    }

    #[test]
    fn args_parse_pr_review_subcommand() {
        let args = Args::try_parse_from([
            "querylens",
            "pr-review",
            "--base",
            "main",
            "--head",
            "HEAD",
            "--dir",
            "models",
            "--glob",
            "*.sql",
        ])
        .expect("pr-review args should parse");
        assert!(matches!(args.command, Some(Commands::PrReview { .. })));
    }

    #[test]
    fn args_parse_pr_review_ci() {
        let args = Args::try_parse_from(["querylens", "pr-review", "--base", "main", "--ci"])
            .expect("pr-review ci args should parse");
        assert!(matches!(
            args.command,
            Some(Commands::PrReview { ci: true, .. })
        ));
    }

    #[test]
    fn args_parse_pr_review_markdown() {
        let args = Args::try_parse_from(["querylens", "pr-review", "--base", "main", "--markdown"])
            .expect("pr-review markdown args should parse");
        assert!(matches!(
            args.command,
            Some(Commands::PrReview { markdown: true, .. })
        ));
    }

    #[test]
    fn args_parse_pr_review_cost_diff() {
        let args =
            Args::try_parse_from(["querylens", "pr-review", "--base", "main", "--cost-diff"])
                .expect("pr-review cost-diff args should parse");
        assert!(matches!(
            args.command,
            Some(Commands::PrReview {
                cost_diff: true,
                ..
            })
        ));
    }

    #[test]
    fn args_parse_lineage_column() {
        let args = Args::try_parse_from([
            "querylens",
            "lineage",
            "examples/revenue.sql",
            "--column",
            "revenue",
        ])
        .expect("lineage column args should parse");
        assert!(matches!(
            args.command,
            Some(Commands::Lineage {
                column: Some(_),
                ..
            })
        ));
    }

    #[test]
    fn args_parse_pg_explain() {
        let args = Args::try_parse_from(["querylens", "pg-explain", "--file", "explain.json"])
            .expect("pg-explain args should parse");
        assert!(matches!(args.command, Some(Commands::PgExplain { .. })));
    }

    #[test]
    fn args_parse_pg_explain_run_with_sql() {
        let args = Args::try_parse_from(["querylens", "pg-explain-run", "--sql", "select 1"])
            .expect("pg-explain-run args should parse");
        assert!(matches!(args.command, Some(Commands::PgExplainRun { .. })));
    }

    #[test]
    fn args_parse_analyze_with_verbose() {
        let args = Args::try_parse_from([
            "querylens",
            "analyze",
            "examples",
            "--glob",
            "*.sql",
            "--verbose",
        ])
        .expect("analyze verbose args should parse");
        assert!(matches!(
            args.command,
            Some(Commands::Analyze { verbose: true, .. })
        ));
    }

    #[test]
    fn args_parse_risk_with_scan_tb() {
        let args = Args::try_parse_from([
            "querylens",
            "risk",
            "examples/query.sql",
            "--scan-tb",
            "2.3",
        ])
        .expect("risk args with scan tb should parse");
        assert_eq!(args.scan_tb, Some(2.3));
        assert_eq!(args.scan_bytes, None);
    }

    #[test]
    fn args_parse_dir_and_fail_threshold() {
        let args = Args::try_parse_from([
            "querylens",
            "--dir",
            "models",
            "--dialect",
            "athena",
            "--glob",
            "*.sql",
            "--fail-on",
            "medium",
        ])
        .expect("args should parse");

        assert_eq!(args.dir.as_deref(), Some(Path::new("models")));
        assert!(matches!(args.dialect, Some(DialectArg::Athena)));
        assert!(matches!(args.fail_on, Some(SeverityArg::Medium)));
    }

    #[test]
    fn args_parse_analyze_changed_only() {
        let args = Args::try_parse_from([
            "querylens",
            "analyze",
            "examples",
            "--glob",
            "*.sql",
            "--changed-only",
        ])
        .expect("args should parse");
        assert!(matches!(
            args.command,
            Some(Commands::Analyze {
                changed_only: true,
                ..
            })
        ));
    }

    #[test]
    fn args_parse_analyze_with_top() {
        let args = Args::try_parse_from([
            "querylens",
            "analyze",
            "examples",
            "--glob",
            "*.sql",
            "--top",
            "10",
        ])
        .expect("args should parse");
        assert!(matches!(
            args.command,
            Some(Commands::Analyze { top: 10, .. })
        ));
    }

    #[test]
    fn args_parse_analyze_with_changed_base() {
        let args = Args::try_parse_from([
            "querylens",
            "analyze",
            "examples",
            "--glob",
            "*.sql",
            "--changed-only",
            "--changed-base",
            "main",
        ])
        .expect("args should parse");
        assert!(matches!(
            args.command,
            Some(Commands::Analyze {
                changed_only: true,
                changed_base: Some(_),
                ..
            })
        ));
    }

    #[test]
    fn read_input_accepts_inline_sql() {
        let args = Args {
            command: None,
            provider: ProviderArg::Openai,
            sql: Some("select 1".to_string()),
            file: None,
            dir: None,
            glob: "*.sql".to_string(),
            dialect: None,
            config: None,
            static_only: false,
            fail_on: None,
            json: false,
            scan_bytes: None,
            scan_tb: None,
            athena_query_execution_id: None,
            athena_region: None,
            stats_file: None,
        };

        let input = read_input(&args).expect("inline SQL should be accepted");
        assert!(matches!(input, InputMode::Sql(_)));
    }

    #[test]
    fn read_input_reads_file() {
        let args = Args {
            command: None,
            provider: ProviderArg::Openai,
            sql: None,
            file: Some(PathBuf::from("examples/query.sql")),
            dir: None,
            glob: "*.sql".to_string(),
            dialect: None,
            config: None,
            static_only: false,
            fail_on: None,
            json: false,
            scan_bytes: None,
            scan_tb: None,
            athena_query_execution_id: None,
            athena_region: None,
            stats_file: None,
        };

        let input = read_input(&args).expect("file input should be accepted");
        match input {
            InputMode::File(_, sql) => assert!(sql.contains("FROM orders o")),
            _ => panic!("expected file input"),
        }
    }

    #[test]
    fn read_input_accepts_directory() {
        let args = Args {
            command: None,
            provider: ProviderArg::Openai,
            sql: None,
            file: None,
            dir: Some(PathBuf::from("examples")),
            glob: "*.sql".to_string(),
            dialect: None,
            config: None,
            static_only: false,
            fail_on: None,
            json: false,
            scan_bytes: None,
            scan_tb: None,
            athena_query_execution_id: None,
            athena_region: None,
            stats_file: None,
        };

        let input = read_input(&args).expect("dir input should be accepted");
        assert!(matches!(input, InputMode::Dir(_)));
    }

    #[test]
    fn read_input_rejects_missing_input() {
        let args = Args {
            command: None,
            provider: ProviderArg::Openai,
            sql: None,
            file: None,
            dir: None,
            glob: "*.sql".to_string(),
            dialect: None,
            config: None,
            static_only: false,
            fail_on: None,
            json: false,
            scan_bytes: None,
            scan_tb: None,
            athena_query_execution_id: None,
            athena_region: None,
            stats_file: None,
        };

        let err = read_input(&args).expect_err("missing input should fail");
        assert!(err
            .to_string()
            .contains("Provide exactly one of --sql, --file, or --dir"));
    }

    #[test]
    fn render_explanation_formats_structured_findings() {
        let parsed = SqlExplanation {
            summary: "Reads recent orders".to_string(),
            tables: vec!["orders".to_string(), "customers".to_string()],
            joins: vec!["INNER JOIN customers ON customer_id".to_string()],
            filters: vec!["created_at >= current_date - interval '30 days'".to_string()],
            risks: vec!["selectivity unknown".to_string()],
            suggestions: vec!["add an index on orders.customer_id".to_string()],
            anti_patterns: vec!["SELECT *".to_string()],
            findings: vec![Finding {
                rule_id: "SELECT_STAR".to_string(),
                severity: Severity::High,
                message: "SELECT *".to_string(),
                why_it_matters: "Scans unnecessary columns".to_string(),
                evidence: vec!["SELECT *".to_string()],
            }],
            estimated_cost_impact: "medium".to_string(),
            confidence: "high".to_string(),
        };

        let rendered = render_explanation(&parsed);

        assert!(rendered.contains("Estimated Cost Impact: medium"));
        assert!(rendered.contains("Confidence: high"));
        assert!(rendered.contains("Findings:"));
        assert!(rendered.contains("[HIGH] SELECT_STAR: SELECT *"));
        assert!(rendered.contains("Evidence: SELECT *"));
    }

    #[test]
    fn render_tables_lists_detected_tables() {
        let output =
            render_tables("SELECT * FROM orders o JOIN customers c ON o.customer_id = c.id");
        assert!(output.contains("orders"));
        assert!(output.contains("customers"));
    }

    #[test]
    fn render_query_explanation_contains_purpose() {
        let output = render_query_explanation(
            "SELECT customer_id, SUM(amount) AS revenue FROM orders GROUP BY customer_id",
        );
        assert!(output.contains("Query explanation"));
        assert!(output.contains("Meaning: revenue per customer"));
        assert!(output.contains("Tables: orders"));
        assert!(output.contains("Aggregation: SUM(amount) AS revenue"));
    }

    #[test]
    fn merge_static_analysis_adds_local_findings() {
        let mut parsed = SqlExplanation {
            summary: "Query review".to_string(),
            tables: vec!["orders".to_string()],
            joins: vec![],
            filters: vec![],
            risks: vec![],
            suggestions: vec![],
            anti_patterns: vec![],
            findings: vec![],
            estimated_cost_impact: "unknown".to_string(),
            confidence: "unknown".to_string(),
        };

        let analysis = analyze_sql("SELECT * FROM orders", AnalysisOptions::default());
        merge_static_analysis(&mut parsed, &analysis);

        assert!(parsed.anti_patterns.iter().any(|x| x == "SELECT *"));
        assert!(parsed.findings.iter().any(|x| x.rule_id == "SELECT_STAR"));
        assert_eq!(parsed.estimated_cost_impact, "high");
        assert_eq!(parsed.confidence, "medium");
    }

    #[test]
    fn simple_glob_matching_works() {
        assert!(matches_pattern(Path::new("models/orders.sql"), "*.sql"));
        assert!(matches_pattern(
            Path::new("models/orders.sql"),
            "*orders.sql"
        ));
        assert!(!matches_pattern(Path::new("models/orders.txt"), "*.sql"));
    }

    #[test]
    fn collect_sql_files_finds_sql_files() {
        let root = temp_test_dir("collect-sql");
        let nested = root.join("nested");
        std::fs::create_dir_all(&nested).expect("nested dir");
        std::fs::write(root.join("one.sql"), "select 1").expect("write file");
        std::fs::write(nested.join("two.sql"), "select 2").expect("write file");
        std::fs::write(root.join("skip.txt"), "nope").expect("write file");

        let files = collect_sql_files(&root, "*.sql").expect("collect files");
        assert_eq!(files.len(), 2);

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn fail_threshold_is_respected() {
        let findings = vec![Finding {
            rule_id: "SELECT_STAR".to_string(),
            severity: Severity::High,
            message: "SELECT *".to_string(),
            why_it_matters: "bad".to_string(),
            evidence: vec![],
        }];

        assert!(should_fail(&findings, Some(Severity::Medium)));
        assert!(should_fail(&findings, Some(Severity::High)));
        assert!(!should_fail(&[], Some(Severity::Low)));
    }

    #[test]
    fn risk_score_uses_max_severity() {
        let findings = vec![
            Finding {
                rule_id: "IN_SUBQUERY".to_string(),
                severity: Severity::Low,
                message: "IN (SELECT ...)".to_string(),
                why_it_matters: "might be less efficient".to_string(),
                evidence: vec![],
            },
            Finding {
                rule_id: "SELECT_STAR".to_string(),
                severity: Severity::High,
                message: "SELECT *".to_string(),
                why_it_matters: "can scan too much".to_string(),
                evidence: vec![],
            },
        ];
        assert_eq!(risk_score(&findings), "HIGH");
    }

    #[test]
    fn estimated_scan_label_prefers_tb() {
        let args = Args {
            command: None,
            provider: ProviderArg::Openai,
            sql: None,
            file: None,
            dir: None,
            glob: "*.sql".to_string(),
            dialect: None,
            config: None,
            static_only: false,
            fail_on: None,
            json: false,
            scan_bytes: Some(1_500_000_000_000),
            scan_tb: Some(2.3),
            athena_query_execution_id: None,
            athena_region: None,
            stats_file: None,
        };
        assert_eq!(
            super::estimated_scan_label(&args, Some("SELECT * FROM orders")).expect("label"),
            "2.30 TB"
        );
    }

    #[test]
    fn estimated_scan_label_can_use_stats_file() {
        let dir = temp_test_dir("stats-file");
        let path = dir.join("stats.json");
        std::fs::write(
            &path,
            r#"{
  "tables": {
    "orders": { "bytes": 1000000000000 },
    "customers": 200000000000
  }
}"#,
        )
        .expect("write stats");

        let args = Args {
            command: None,
            provider: ProviderArg::Openai,
            sql: None,
            file: None,
            dir: None,
            glob: "*.sql".to_string(),
            dialect: None,
            config: None,
            static_only: false,
            fail_on: None,
            json: false,
            scan_bytes: None,
            scan_tb: None,
            athena_query_execution_id: None,
            athena_region: None,
            stats_file: Some(path.clone()),
        };

        let label = super::estimated_scan_label(
            &args,
            Some("SELECT * FROM orders o JOIN customers c ON o.customer_id = c.id"),
        )
        .expect("label");
        assert_eq!(label, "1.20 TB");

        std::fs::remove_file(path).expect("cleanup file");
        std::fs::remove_dir_all(dir).expect("cleanup dir");
    }

    #[test]
    fn estimated_scan_label_reduces_stats_estimate_for_date_filter() {
        let dir = temp_test_dir("stats-file-filter");
        let path = dir.join("stats.json");
        std::fs::write(
            &path,
            r#"{
  "tables": {
    "orders": { "bytes": 1500000000000 }
  }
}"#,
        )
        .expect("write stats");

        let args = Args {
            command: None,
            provider: ProviderArg::Openai,
            sql: None,
            file: None,
            dir: None,
            glob: "*.sql".to_string(),
            dialect: None,
            config: None,
            static_only: false,
            fail_on: None,
            json: false,
            scan_bytes: None,
            scan_tb: None,
            athena_query_execution_id: None,
            athena_region: None,
            stats_file: Some(path.clone()),
        };

        let label = super::estimated_scan_label(
            &args,
            Some("SELECT * FROM orders WHERE order_date >= DATE '2026-01-01'"),
        )
        .expect("label");
        // With no partition metadata, we assume a partial scan (~70% of table bytes)
        assert_eq!(label, "1.05 TB");

        std::fs::remove_file(path).expect("cleanup file");
        std::fs::remove_dir_all(dir).expect("cleanup dir");
    }

    #[test]
    fn simulate_query_appends_limit_for_select_queries() {
        let sql = "SELECT id FROM orders";
        let simulated = simulate_query(sql, 25);
        assert!(simulated.contains("LIMIT 25;"));
    }

    #[test]
    fn simulate_query_ignores_limit_word_in_comment() {
        let sql = "-- limit 1\nSELECT id FROM orders";
        let simulated = simulate_query(sql, 25);
        assert!(simulated.contains("LIMIT 25;"));
    }

    #[test]
    fn simulate_query_does_not_treat_alias_as_limit_clause() {
        let sql = "SELECT total AS limit FROM orders";
        let simulated = simulate_query(sql, 25);
        assert!(simulated.contains("LIMIT 25;"));
    }

    #[test]
    fn extracts_suppressed_rules_from_comment() {
        let sql = "-- querylens: disable=SELECT_STAR, MISSING_WHERE\nSELECT * FROM orders";
        let rules = extract_suppressed_rules(sql);
        assert!(rules.contains("SELECT_STAR"));
        assert!(rules.contains("MISSING_WHERE"));
    }

    #[test]
    fn inline_suppression_removes_matching_findings() {
        let sql = "-- querylens: disable=SELECT_STAR\nSELECT * FROM orders";
        let mut analysis = analyze_sql(sql, AnalysisOptions::default());
        apply_inline_suppressions_to_analysis(&mut analysis, sql);
        assert!(!analysis.findings.iter().any(|f| f.rule_id == "SELECT_STAR"));
        assert!(!analysis.anti_patterns.iter().any(|p| p == "SELECT *"));
    }

    #[test]
    fn guard_threshold_blocks_only_above_max_risk() {
        let findings = vec![Finding {
            rule_id: "SELECT_STAR".to_string(),
            severity: Severity::High,
            message: "SELECT *".to_string(),
            why_it_matters: "bad".to_string(),
            evidence: vec![],
        }];

        let reasons = guard_block_reasons(&findings, Severity::High, &[]);
        assert!(reasons.is_empty());

        let reasons = guard_block_reasons(&findings, Severity::Medium, &[]);
        assert!(!reasons.is_empty());
    }

    #[test]
    fn render_pr_review_includes_pass_status() {
        let report = PrReviewReport {
            base: "HEAD~1".to_string(),
            head: "HEAD".to_string(),
            summary: PrReviewSummary {
                status: "PASS".to_string(),
                changed_sql_files: 1,
                new_high_risk_queries: 0,
                partition_filter_regressions: 0,
                order_by_without_limit_regressions: 0,
                possible_join_amplification_regressions: 0,
                scan_cost_increase_files: 0,
            },
            files: vec![PrFileDelta {
                path: "models/example.sql".to_string(),
                previous_risk: "HIGH".to_string(),
                current_risk: "HIGH".to_string(),
                risk_trend: "unchanged".to_string(),
                new_issues: vec![],
                resolved_issues: vec![],
                persistent_risk_factors: vec!["SELECT_STAR".to_string()],
                estimated_scan_from: "unknown".to_string(),
                estimated_scan_to: "unknown".to_string(),
                scan_delta: "unknown".to_string(),
                cost_regression: None,
                cost_regression_reason: None,
                cost_recommendation: None,
                scan_increase_factor: None,
            }],
        };

        let rendered = render_pr_review(&report);
        assert!(rendered.contains("PR status: PASS"));
        assert!(rendered.contains("Base: HEAD~1"));
        assert!(rendered.contains("Still risky because:"));
    }

    #[test]
    fn render_pr_review_ci_is_compact() {
        let report = PrReviewReport {
            base: "main".to_string(),
            head: "HEAD".to_string(),
            summary: PrReviewSummary {
                status: "FAIL".to_string(),
                changed_sql_files: 3,
                new_high_risk_queries: 1,
                partition_filter_regressions: 1,
                order_by_without_limit_regressions: 0,
                possible_join_amplification_regressions: 1,
                scan_cost_increase_files: 2,
            },
            files: vec![],
        };

        let rendered = render_pr_review_ci(&report);
        assert!(rendered.contains("PR status: FAIL"));
        assert!(rendered.contains("Changed SQL files: 3"));
        assert!(!rendered.contains("File:"));
    }

    #[test]
    fn render_pr_review_markdown_uses_markdown_sections() {
        let report = PrReviewReport {
            base: "main".to_string(),
            head: "HEAD".to_string(),
            summary: PrReviewSummary {
                status: "PASS".to_string(),
                changed_sql_files: 1,
                new_high_risk_queries: 0,
                partition_filter_regressions: 0,
                order_by_without_limit_regressions: 0,
                possible_join_amplification_regressions: 0,
                scan_cost_increase_files: 0,
            },
            files: vec![PrFileDelta {
                path: "models/example.sql".to_string(),
                previous_risk: "LOW".to_string(),
                current_risk: "MEDIUM".to_string(),
                risk_trend: "regressed".to_string(),
                new_issues: vec!["SELECT_STAR".to_string()],
                resolved_issues: vec![],
                persistent_risk_factors: vec!["MISSING_WHERE".to_string()],
                estimated_scan_from: "unknown".to_string(),
                estimated_scan_to: "1.20 TB".to_string(),
                scan_delta: "+1.20 TB".to_string(),
                cost_regression: Some("MEDIUM".to_string()),
                cost_regression_reason: Some(
                    "Filter removed: order_date >= CURRENT_DATE - INTERVAL '30 days'".to_string(),
                ),
                cost_recommendation: Some(
                    "Restore a selective WHERE or partition predicate.".to_string(),
                ),
                scan_increase_factor: Some("4.0x".to_string()),
            }],
        };

        let rendered = render_pr_review_markdown(&report);
        assert!(rendered.contains("# SQL Inspect PR Review"));
        assert!(rendered.contains("## `models/example.sql`"));
        assert!(rendered.contains("**PR status:** **PASS**"));
    }

    #[test]
    fn render_pr_review_cost_diff_highlights_scan_regression() {
        let report = PrReviewReport {
            base: "main".to_string(),
            head: "HEAD".to_string(),
            summary: PrReviewSummary {
                status: "FAIL".to_string(),
                changed_sql_files: 1,
                new_high_risk_queries: 1,
                partition_filter_regressions: 1,
                order_by_without_limit_regressions: 0,
                possible_join_amplification_regressions: 0,
                scan_cost_increase_files: 1,
            },
            files: vec![PrFileDelta {
                path: "models/revenue.sql".to_string(),
                previous_risk: "LOW".to_string(),
                current_risk: "HIGH".to_string(),
                risk_trend: "regressed".to_string(),
                new_issues: vec!["ATHENA_MISSING_PARTITION_FILTER".to_string()],
                resolved_issues: vec![],
                persistent_risk_factors: vec![],
                estimated_scan_from: "22 GB".to_string(),
                estimated_scan_to: "1.40 TB".to_string(),
                scan_delta: "+1.38 TB".to_string(),
                cost_regression: Some("HIGH".to_string()),
                cost_regression_reason: Some(
                    "Partition filter removed or missing on orders".to_string(),
                ),
                cost_recommendation: Some(
                    "Restore a partition predicate on the scanned table.".to_string(),
                ),
                scan_increase_factor: Some("63.6x".to_string()),
            }],
        };

        let rendered = render_pr_review_cost_diff(&report);
        assert!(rendered.contains("SQL Cost Regression"));
        assert!(rendered.contains("Cost regression: HIGH"));
        assert!(rendered.contains("Increase: 63.6x"));
        assert!(rendered.contains("Recommendation:"));
    }

    #[test]
    fn render_lineage_can_filter_to_single_column() {
        let sql = "SELECT customer_id, SUM(amount) AS revenue FROM orders GROUP BY customer_id";
        let rendered = render_lineage(Path::new("examples/revenue.sql"), sql, Some("revenue"));
        assert!(rendered.contains("revenue"));
        assert!(!rendered.contains("customer_id\n └─ customer_id"));
    }

    #[test]
    fn render_risk_summary_is_compact() {
        let report = super::build_risk_report(
            Path::new("examples/query.sql"),
            &[Finding {
                rule_id: "SELECT_STAR".to_string(),
                severity: Severity::High,
                message: "SELECT *".to_string(),
                why_it_matters: "Scans unnecessary columns".to_string(),
                evidence: vec![],
            }],
            "2.30 TB".to_string(),
        );

        let rendered = render_risk_summary(&report);
        assert!(rendered.contains("SQL Inspect Risk"));
        assert!(rendered.contains("Risk: HIGH"));
        assert!(rendered.contains("Top reasons:"));
    }

    #[test]
    fn parse_pg_explain_basic() {
        let json = r#"
[
  {
    "Plan": {
      "Node Type": "Seq Scan",
      "Relation Name": "orders",
      "Actual Rows": 1000,
      "Actual Loops": 1
    },
    "Planning Time": 1.23,
    "Execution Time": 12.34
  }
]
"#;
        let summary = parse_pg_explain_summary(json).expect("parse explain");
        assert_eq!(summary.execution_time_ms, Some(12.34));
        assert_eq!(summary.planning_time_ms, Some(1.23));
        assert!(summary.seq_scans.contains(&"orders".to_string()));
        assert_eq!(summary.total_rows, Some(1000.0));

        let rendered = render_pg_explain(&summary);
        assert!(rendered.contains("Execution time"));
        assert!(rendered.contains("Seq scans"));
    }

    #[test]
    fn render_guard_report_includes_fail_status() {
        let report = GuardReport {
            policy: "default".to_string(),
            status: "FAIL".to_string(),
            risk: "HIGH".to_string(),
            blocking_violations: vec![
                "FULL_TABLE_SCAN_LIKELY".to_string(),
                "ORDER_BY_WITHOUT_LIMIT".to_string(),
            ],
            why_blocked: Some("Likely scans too much data".to_string()),
        };

        let rendered = render_guard_report(&report);
        assert!(rendered.contains("SQL Inspect Guard"));
        assert!(rendered.contains("Status: FAIL"));
        assert!(rendered.contains("Blocking violations"));
        assert!(rendered.contains("Exit code: 2"));
    }

    #[test]
    fn rule_controls_can_disable_findings() {
        let mut parsed = SqlExplanation {
            summary: "Query review".to_string(),
            tables: vec![],
            joins: vec![],
            filters: vec![],
            risks: vec![],
            suggestions: vec![],
            anti_patterns: vec!["SELECT *".to_string()],
            findings: vec![Finding {
                rule_id: "SELECT_STAR".to_string(),
                severity: Severity::High,
                message: "SELECT *".to_string(),
                why_it_matters: "bad".to_string(),
                evidence: vec!["SELECT *".to_string()],
            }],
            estimated_cost_impact: "high".to_string(),
            confidence: "high".to_string(),
        };

        let mut rules = HashMap::new();
        rules.insert(
            "SELECT_STAR".to_string(),
            RuleControl {
                enabled: Some(false),
                severity: None,
            },
        );
        let config = SqlInspectConfig {
            rules: Some(rules),
            ..SqlInspectConfig::default()
        };

        apply_rule_controls(&mut parsed, &config);
        assert!(parsed.findings.is_empty());
        assert!(!parsed.anti_patterns.iter().any(|x| x == "SELECT *"));
    }

    #[test]
    fn rule_controls_can_override_severity() {
        let mut parsed = SqlExplanation {
            summary: "Query review".to_string(),
            tables: vec![],
            joins: vec![],
            filters: vec![],
            risks: vec![],
            suggestions: vec![],
            anti_patterns: vec![],
            findings: vec![Finding {
                rule_id: "MISSING_WHERE".to_string(),
                severity: Severity::Medium,
                message: "No WHERE clause".to_string(),
                why_it_matters: "bad".to_string(),
                evidence: vec![],
            }],
            estimated_cost_impact: "medium".to_string(),
            confidence: "high".to_string(),
        };

        let mut rules = HashMap::new();
        rules.insert(
            "MISSING_WHERE".to_string(),
            RuleControl {
                enabled: Some(true),
                severity: Some("low".to_string()),
            },
        );
        let config = SqlInspectConfig {
            rules: Some(rules),
            ..SqlInspectConfig::default()
        };

        apply_rule_controls(&mut parsed, &config);
        assert_eq!(parsed.findings[0].severity, Severity::Low);
    }

    fn temp_test_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("querylens-main-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }
}
