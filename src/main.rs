use clap::{Parser, ValueEnum};
use sql_inspect::analyzer::{analyze_sql, AnalysisOptions, Dialect, StaticAnalysis};
use sql_inspect::config::{load_config, SqlInspectConfig};
use sql_inspect::error::AppError;
use sql_inspect::insights::{explain_query, extract_lineage_report, extract_tables};
use sql_inspect::prompt::{build_prompt, parse_sql_explanation, Finding, Severity, SqlExplanation};
use sql_inspect::providers::bedrock::BedrockProvider;
use sql_inspect::providers::local::LocalProvider;
use sql_inspect::providers::openai::OpenAIProvider;
use sql_inspect::providers::LlmProvider;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

#[derive(ValueEnum, Clone, Debug)]
enum ProviderArg {
    Openai,
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
    },
    Risk {
        file: PathBuf,
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
    Analyze {
        dir: PathBuf,
        #[arg(long, default_value = "*.sql")]
        glob: String,
        #[arg(long, default_value_t = false)]
        changed_only: bool,
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
    },
}

#[derive(Parser, Debug)]
#[command(name = "sql-inspect")]
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

    #[arg(long, global = true)]
    athena_query_execution_id: Option<String>,

    #[arg(long, global = true)]
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
struct PrFileReport {
    path: String,
    previous_risk: String,
    current_risk: String,
    new_issues: Vec<String>,
    removed_issues: Vec<String>,
    estimated_scan_from: String,
    estimated_scan_to: String,
}

#[derive(Debug, serde::Serialize)]
struct PrSummaryReport {
    changed_sql_files: usize,
    new_high_risk_queries: usize,
    partition_filter_regressions: usize,
    order_by_without_limit_regressions: usize,
    possible_join_amplification_regressions: usize,
}

#[derive(Debug, serde::Serialize)]
struct PrReviewReport {
    summary: PrSummaryReport,
    files: Vec<PrFileReport>,
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
        let Some(idx) = lower.find("sql-inspect: disable=") else {
            continue;
        };
        let raw = &line[idx + "sql-inspect: disable=".len()..];
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
        if matches_pattern(&candidate, pattern) {
            files.push(candidate);
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
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

fn render_lineage(path: &Path, sql: &str) -> String {
    let report = extract_lineage_report(sql);
    let mut out = String::new();
    out.push_str(&format!("{}\n", path.display()));

    out.push_str("Projections:\n");
    for item in report.projections {
        out.push_str(&item.output);
        out.push('\n');
        out.push_str(" └─ ");
        out.push_str(&item.expression);
        out.push('\n');
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
    out.push_str("Purpose: ");
    out.push_str(&explanation.purpose);
    out.push('\n');

    out.push_str("Tables: ");
    if explanation.tables.is_empty() {
        out.push_str("unknown");
    } else {
        out.push_str(&explanation.tables.join(", "));
    }
    out.push('\n');

    out.push_str("Aggregation: ");
    if explanation.aggregations.is_empty() {
        out.push_str("none");
    } else {
        out.push_str(&explanation.aggregations.join(", "));
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
    for table in tables {
        if let Some(bytes) = lookup_table_bytes(&value, &table) {
            total = total.saturating_add(bytes);
            matched = true;
        }
    }

    if matched {
        Ok(Some(total))
    } else {
        Ok(None)
    }
}

fn lookup_table_bytes(value: &serde_json::Value, table: &str) -> Option<u64> {
    let direct = value.get(table).and_then(parse_bytes_value);
    if direct.is_some() {
        return direct;
    }
    value
        .get("tables")
        .and_then(|v| v.get(table))
        .and_then(parse_bytes_value)
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

    format!("SELECT *\nFROM (\n{trimmed}\n) AS sql_inspect_preview\nLIMIT {limit};")
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
    out.push_str("\nEstimated scan: ");
    out.push_str(&report.estimated_scan);
    out.push('\n');
    out
}

fn render_folder_summary(
    file_count: usize,
    counts: &std::collections::BTreeMap<String, usize>,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("Analyzed {} SQL files\n", file_count));
    out.push_str("Warnings:\n");
    if counts.is_empty() {
        out.push_str("- none\n");
    } else {
        for (rule, count) in counts {
            out.push_str(&format!("- {} {}\n", count, rule));
        }
    }
    out
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

fn finding_key(finding: &Finding) -> String {
    format!(
        "{}|{}|{}|{}",
        finding.rule_id,
        severity_label(&finding.severity),
        finding.message,
        finding.evidence.join(";")
    )
}

fn bytes_to_tb_label(bytes: Option<u64>) -> String {
    match bytes {
        Some(bytes) => format!("{:.2} TB", bytes as f64 / 1_000_000_000_000_f64),
        None => "unknown".to_string(),
    }
}

fn estimate_scan_bytes(args: &Args, sql: &str) -> anyhow::Result<Option<u64>> {
    if let Some(tb) = args.scan_tb {
        let bytes = (tb * 1_000_000_000_000_f64) as u64;
        return Ok(Some(bytes));
    }
    if let Some(bytes) = args.scan_bytes {
        return Ok(Some(bytes));
    }
    if let Some(bytes) = estimate_scan_from_stats_file(args, Some(sql))? {
        return Ok(Some(bytes));
    }
    Ok(None)
}

fn has_rule(findings: &[Finding], rule_id: &str) -> bool {
    findings.iter().any(|f| f.rule_id == rule_id)
}

fn render_pr_review(report: &PrReviewReport) -> String {
    let mut out = String::new();
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
        if !file.new_issues.is_empty() {
            out.push_str("New issues:\n");
            for issue in &file.new_issues {
                out.push_str("- ");
                out.push_str(issue);
                out.push('\n');
            }
        }
        if !file.removed_issues.is_empty() {
            out.push_str("Removed issues:\n");
            for issue in &file.removed_issues {
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
    }
    out
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    let config = load_config(args.config.as_deref())?;

    if let Some(command) = &args.command {
        match command {
            Commands::Lineage { file } => {
                let sql = read_sql_file(file)?;
                print!("{}", render_lineage(file, &sql));
                return Ok(());
            }
            Commands::Risk { file } => {
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

                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "file": file.display().to_string(),
                            "blocked": !block_reasons.is_empty(),
                            "risk_score": risk_score(&parsed.findings),
                            "reasons": block_reasons,
                            "findings": parsed.findings
                        }))?
                    );
                } else if block_reasons.is_empty() {
                    println!("ALLOW {}", file.display());
                } else {
                    println!("BLOCK {}", file.display());
                    for reason in &block_reasons {
                        println!("- {reason}");
                    }
                }

                if !block_reasons.is_empty() {
                    std::process::exit(1);
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
            Commands::Analyze {
                dir,
                glob,
                changed_only,
            } => {
                let mut options = analysis_options(&config);
                if let Some(dialect) = args.dialect {
                    options.dialect = cli_dialect(dialect);
                }
                let files = if *changed_only {
                    collect_changed_sql_files(dir, glob)?
                } else {
                    collect_sql_files(dir, glob)?
                };
                let mut counts = std::collections::BTreeMap::<String, usize>::new();

                for file in &files {
                    let sql = std::fs::read_to_string(file)?;
                    let mut analysis = analyze_sql(&sql, options);
                    apply_inline_suppressions_to_analysis(&mut analysis, &sql);
                    let mut parsed = build_static_explanation(&analysis);
                    apply_rule_controls(&mut parsed, &config);
                    for finding in &parsed.findings {
                        *counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
                    }
                }

                print!("{}", render_folder_summary(files.len(), &counts));
                return Ok(());
            }
            Commands::PrReview {
                base,
                head,
                dir,
                glob,
            } => {
                let mut options = analysis_options(&config);
                if let Some(dialect) = args.dialect {
                    options.dialect = cli_dialect(dialect);
                }

                let files = collect_changed_sql_files_between_refs(dir, glob, base, head)?;
                let mut file_reports = Vec::new();
                let mut summary = PrSummaryReport {
                    changed_sql_files: files.len(),
                    new_high_risk_queries: 0,
                    partition_filter_regressions: 0,
                    order_by_without_limit_regressions: 0,
                    possible_join_amplification_regressions: 0,
                };

                for file in files {
                    let previous_sql = read_file_at_ref(&file, base)?;
                    let current_sql = read_file_at_ref(&file, head)?;
                    let Some(current_sql) = current_sql else {
                        continue;
                    };

                    let previous = previous_sql
                        .as_ref()
                        .map(|sql| build_effective_static_explanation(sql, options, &config));
                    let current =
                        build_effective_static_explanation(&current_sql, options, &config);

                    let previous_findings = previous
                        .as_ref()
                        .map(|p| p.findings.clone())
                        .unwrap_or_default();
                    let current_findings = current.findings.clone();

                    let previous_keys: HashSet<String> =
                        previous_findings.iter().map(finding_key).collect();
                    let current_keys: HashSet<String> =
                        current_findings.iter().map(finding_key).collect();

                    let new_issues: Vec<String> = current_findings
                        .iter()
                        .filter(|f| !previous_keys.contains(&finding_key(f)))
                        .map(|f| format!("{}: {}", f.rule_id, f.message))
                        .collect();
                    let removed_issues: Vec<String> = previous_findings
                        .iter()
                        .filter(|f| !current_keys.contains(&finding_key(f)))
                        .map(|f| format!("{}: {}", f.rule_id, f.message))
                        .collect();

                    let prev_risk = risk_score(&previous_findings).to_string();
                    let curr_risk = risk_score(&current_findings).to_string();
                    let prev_rank = max_finding_severity(&previous_findings).rank();
                    let curr_rank = max_finding_severity(&current_findings).rank();
                    if curr_rank > prev_rank && curr_risk == "HIGH" {
                        summary.new_high_risk_queries += 1;
                    }

                    if !has_rule(&previous_findings, "ATHENA_MISSING_PARTITION_FILTER")
                        && has_rule(&current_findings, "ATHENA_MISSING_PARTITION_FILTER")
                    {
                        summary.partition_filter_regressions += 1;
                    }
                    if !has_rule(&previous_findings, "ATHENA_ORDER_BY_WITHOUT_LIMIT")
                        && has_rule(&current_findings, "ATHENA_ORDER_BY_WITHOUT_LIMIT")
                    {
                        summary.order_by_without_limit_regressions += 1;
                    }
                    if !has_rule(&previous_findings, "POSSIBLE_CARTESIAN_JOIN")
                        && has_rule(&current_findings, "POSSIBLE_CARTESIAN_JOIN")
                    {
                        summary.possible_join_amplification_regressions += 1;
                    }

                    let scan_from = previous_sql
                        .as_ref()
                        .map(|sql| estimate_scan_bytes(&args, sql))
                        .transpose()?
                        .flatten();
                    let scan_to = estimate_scan_bytes(&args, &current_sql)?;

                    file_reports.push(PrFileReport {
                        path: file.display().to_string(),
                        previous_risk: prev_risk,
                        current_risk: curr_risk,
                        new_issues,
                        removed_issues,
                        estimated_scan_from: bytes_to_tb_label(scan_from),
                        estimated_scan_to: bytes_to_tb_label(scan_to),
                    });
                }

                let report = PrReviewReport {
                    summary,
                    files: file_reports,
                };

                if args.json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    print!("{}", render_pr_review(&report));
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
        read_input, render_explanation, render_query_explanation, render_tables, risk_score,
        should_fail, simulate_query, Args, Commands, DialectArg, InputMode, ProviderArg,
        SeverityArg,
    };
    use clap::Parser;
    use sql_inspect::analyzer::{analyze_sql, AnalysisOptions};
    use sql_inspect::config::{RuleControl, SqlInspectConfig};
    use sql_inspect::prompt::{Finding, Severity, SqlExplanation};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    #[test]
    fn args_parse_inline_sql() {
        let args =
            Args::try_parse_from(["sql-inspect", "--sql", "select 1"]).expect("args should parse");

        assert!(matches!(args.provider, ProviderArg::Openai));
        assert_eq!(args.sql.as_deref(), Some("select 1"));
        assert!(args.command.is_none());
        assert!(args.file.is_none());
        assert!(!args.json);
    }

    #[test]
    fn args_parse_tables_subcommand() {
        let args = Args::try_parse_from(["sql-inspect", "tables", "examples/query.sql"])
            .expect("subcommand args should parse");
        assert!(matches!(args.command, Some(Commands::Tables { .. })));
    }

    #[test]
    fn args_parse_risk_subcommand() {
        let args = Args::try_parse_from(["sql-inspect", "risk", "examples/query.sql"])
            .expect("subcommand args should parse");
        assert!(matches!(args.command, Some(Commands::Risk { .. })));
    }

    #[test]
    fn args_parse_guard_subcommand() {
        let args = Args::try_parse_from([
            "sql-inspect",
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
            "sql-inspect",
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
            "sql-inspect",
            "pr-review",
            "--base",
            "main",
            "--head",
            "HEAD",
            "--dir",
            "examples",
            "--glob",
            "*.sql",
        ])
        .expect("pr-review args should parse");
        assert!(matches!(args.command, Some(Commands::PrReview { .. })));
    }

    #[test]
    fn args_parse_risk_with_scan_tb() {
        let args = Args::try_parse_from([
            "sql-inspect",
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
            "sql-inspect",
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
            "sql-inspect",
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
        let output = render_query_explanation("SELECT SUM(amount) AS revenue FROM orders");
        assert!(output.contains("Purpose:"));
        assert!(output.contains("Aggregation: SUM"));
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
        let sql = "-- sql-inspect: disable=SELECT_STAR, MISSING_WHERE\nSELECT * FROM orders";
        let rules = extract_suppressed_rules(sql);
        assert!(rules.contains("SELECT_STAR"));
        assert!(rules.contains("MISSING_WHERE"));
    }

    #[test]
    fn inline_suppression_removes_matching_findings() {
        let sql = "-- sql-inspect: disable=SELECT_STAR\nSELECT * FROM orders";
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
            std::env::temp_dir().join(format!("sql-inspect-main-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }
}
