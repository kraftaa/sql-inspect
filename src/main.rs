use clap::{Parser, ValueEnum};
use sql_ai_explainer::analyzer::{analyze_sql, AnalysisOptions, Dialect, StaticAnalysis};
use sql_ai_explainer::config::{load_config, SqlInspectConfig};
use sql_ai_explainer::error::AppError;
use sql_ai_explainer::insights::{explain_query, extract_lineage, extract_tables};
use sql_ai_explainer::prompt::{
    build_prompt, parse_sql_explanation, Finding, Severity, SqlExplanation,
};
use sql_ai_explainer::providers::bedrock::BedrockProvider;
use sql_ai_explainer::providers::openai::OpenAIProvider;
use sql_ai_explainer::providers::LlmProvider;
use std::path::{Path, PathBuf};

#[derive(ValueEnum, Clone, Debug)]
enum ProviderArg {
    Openai,
    Bedrock,
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
    },
}

#[derive(Parser, Debug)]
#[command(name = "sql-ai-explainer")]
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

    #[arg(long, value_enum)]
    dialect: Option<DialectArg>,

    #[arg(long)]
    config: Option<PathBuf>,

    #[arg(long)]
    static_only: bool,

    #[arg(long, value_enum)]
    fail_on: Option<SeverityArg>,

    #[arg(long)]
    json: bool,
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
    }
}

async fn analyze_single_sql(
    sql: &str,
    static_only: bool,
    args: &Args,
    options: AnalysisOptions,
) -> anyhow::Result<SqlExplanation> {
    let analysis = analyze_sql(sql, options);

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
    let lineage = extract_lineage(sql);
    let mut out = String::new();
    out.push_str(&format!("{}\n", path.display()));
    for item in lineage {
        out.push_str(&item.output);
        out.push('\n');
        out.push_str(" └─ ");
        out.push_str(&item.expression);
        out.push('\n');
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
            Commands::Analyze { dir, glob } => {
                let mut options = analysis_options(&config);
                if let Some(dialect) = args.dialect {
                    options.dialect = cli_dialect(dialect);
                }
                let files = collect_sql_files(dir, glob)?;
                let mut counts = std::collections::BTreeMap::<String, usize>::new();

                for file in &files {
                    let sql = std::fs::read_to_string(file)?;
                    let analysis = analyze_sql(&sql, options);
                    let mut parsed = build_static_explanation(&analysis);
                    apply_rule_controls(&mut parsed, &config);
                    for finding in &parsed.findings {
                        *counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
                    }
                }

                print!("{}", render_folder_summary(files.len(), &counts));
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
        apply_rule_controls, collect_sql_files, matches_pattern, merge_static_analysis, read_input,
        render_explanation, render_query_explanation, render_tables, should_fail, Args, Commands,
        DialectArg, InputMode, ProviderArg, SeverityArg,
    };
    use clap::Parser;
    use sql_ai_explainer::analyzer::{analyze_sql, AnalysisOptions};
    use sql_ai_explainer::config::{RuleControl, SqlInspectConfig};
    use sql_ai_explainer::prompt::{Finding, Severity, SqlExplanation};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    #[test]
    fn args_parse_inline_sql() {
        let args = Args::try_parse_from(["sql-ai-explainer", "--sql", "select 1"])
            .expect("args should parse");

        assert!(matches!(args.provider, ProviderArg::Openai));
        assert_eq!(args.sql.as_deref(), Some("select 1"));
        assert!(args.command.is_none());
        assert!(args.file.is_none());
        assert!(!args.json);
    }

    #[test]
    fn args_parse_tables_subcommand() {
        let args = Args::try_parse_from(["sql-ai-explainer", "tables", "examples/query.sql"])
            .expect("subcommand args should parse");
        assert!(matches!(args.command, Some(Commands::Tables { .. })));
    }

    #[test]
    fn args_parse_dir_and_fail_threshold() {
        let args = Args::try_parse_from([
            "sql-ai-explainer",
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
        assert_eq!(parsed.estimated_cost_impact, "medium");
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
