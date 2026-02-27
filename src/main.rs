use clap::{Parser, ValueEnum};
use sql_ai_explainer::error::AppError;
use sql_ai_explainer::prompt::{build_prompt, parse_sql_explanation, SqlExplanation};
use sql_ai_explainer::providers::bedrock::BedrockProvider;
use sql_ai_explainer::providers::openai::OpenAIProvider;
use sql_ai_explainer::providers::LlmProvider;

#[derive(ValueEnum, Clone, Debug)]
enum ProviderArg {
    Openai,
    Bedrock,
}

#[derive(Parser, Debug)]
#[command(name = "sql-ai-explainer")]
struct Args {
    #[arg(long, value_enum, default_value = "openai")]
    provider: ProviderArg,

    #[arg(long)]
    sql: Option<String>,

    #[arg(long)]
    file: Option<std::path::PathBuf>,

    #[arg(long)]
    json: bool,
}

fn env(name: &'static str) -> Result<String, AppError> {
    std::env::var(name).map_err(|_| AppError::MissingEnv(name))
}

fn read_sql_input(args: &Args) -> anyhow::Result<String> {
    match (&args.sql, &args.file) {
        (Some(s), None) => Ok(s.clone()),
        (None, Some(p)) => Ok(std::fs::read_to_string(p)?),
        _ => Err(anyhow::anyhow!("Provide exactly one of --sql or --file")),
    }
}

fn render_explanation(parsed: &SqlExplanation) -> String {
    let mut out = String::new();

    out.push_str("\nSummary:\n");
    out.push_str(&parsed.summary);
    out.push_str("\n\n");

    if !parsed.tables.is_empty() {
        out.push_str("Tables: ");
        out.push_str(&parsed.tables.join(", "));
        out.push('\n');
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

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    let sql = match read_sql_input(&args) {
        Ok(sql) => sql,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let prompt = build_prompt(&sql);

    let provider: Box<dyn LlmProvider> = match args.provider {
        ProviderArg::Openai => {
            let key = env("OPENAI_API_KEY")?;
            let model =
                std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4.1-mini".to_string());
            Box::new(OpenAIProvider::new(key, model))
        }
        ProviderArg::Bedrock => {
            let model_id = env("BEDROCK_MODEL_ID")?;
            let p = BedrockProvider::new(model_id).await?;
            Box::new(p)
        }
    };

    let raw_json = provider.explain_sql_json(&prompt).await?;

    if args.json {
        println!("{raw_json}");
        return Ok(());
    }

    let parsed = parse_sql_explanation(&raw_json)?;
    print!("{}", render_explanation(&parsed));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{read_sql_input, render_explanation, Args, ProviderArg};
    use clap::Parser;
    use sql_ai_explainer::prompt::SqlExplanation;

    #[test]
    fn args_parse_inline_sql() {
        let args = Args::try_parse_from(["sql-ai-explainer", "--sql", "select 1"])
            .expect("args should parse");

        assert!(matches!(args.provider, ProviderArg::Openai));
        assert_eq!(args.sql.as_deref(), Some("select 1"));
        assert!(args.file.is_none());
        assert!(!args.json);
    }

    #[test]
    fn args_parse_file_and_provider() {
        let args = Args::try_parse_from([
            "sql-ai-explainer",
            "--provider",
            "bedrock",
            "--file",
            "examples/query.sql",
            "--json",
        ])
        .expect("args should parse");

        assert!(matches!(args.provider, ProviderArg::Bedrock));
        assert_eq!(
            args.file.as_deref(),
            Some(std::path::Path::new("examples/query.sql"))
        );
        assert!(args.json);
    }

    #[test]
    fn read_sql_input_accepts_inline_sql() {
        let args = Args {
            provider: ProviderArg::Openai,
            sql: Some("select 1".to_string()),
            file: None,
            json: false,
        };

        let sql = read_sql_input(&args).expect("inline SQL should be accepted");
        assert_eq!(sql, "select 1");
    }

    #[test]
    fn read_sql_input_reads_file() {
        let args = Args {
            provider: ProviderArg::Openai,
            sql: None,
            file: Some(std::path::PathBuf::from("examples/query.sql")),
            json: false,
        };

        let sql = read_sql_input(&args).expect("file input should be accepted");
        assert!(sql.contains("FROM orders o"));
    }

    #[test]
    fn read_sql_input_rejects_missing_input() {
        let args = Args {
            provider: ProviderArg::Openai,
            sql: None,
            file: None,
            json: false,
        };

        let err = read_sql_input(&args).expect_err("missing input should fail");
        assert!(err
            .to_string()
            .contains("Provide exactly one of --sql or --file"));
    }

    #[test]
    fn read_sql_input_rejects_both_inputs() {
        let args = Args {
            provider: ProviderArg::Openai,
            sql: Some("select 1".to_string()),
            file: Some(std::path::PathBuf::from("examples/query.sql")),
            json: false,
        };

        let err = read_sql_input(&args).expect_err("both inputs should fail");
        assert!(err
            .to_string()
            .contains("Provide exactly one of --sql or --file"));
    }

    #[test]
    fn render_explanation_formats_all_sections() {
        let parsed = SqlExplanation {
            summary: "Reads recent orders".to_string(),
            tables: vec!["orders".to_string(), "customers".to_string()],
            joins: vec!["INNER JOIN customers ON customer_id".to_string()],
            filters: vec!["created_at >= current_date - interval '30 days'".to_string()],
            risks: vec!["selectivity unknown".to_string()],
            suggestions: vec!["add an index on orders.customer_id".to_string()],
        };

        let rendered = render_explanation(&parsed);

        assert!(rendered.contains("\nSummary:\nReads recent orders\n"));
        assert!(rendered.contains("Tables: orders, customers"));
        assert!(rendered.contains("\nJoins:\n - INNER JOIN customers ON customer_id\n"));
        assert!(
            rendered.contains("\nFilters:\n - created_at >= current_date - interval '30 days'\n")
        );
        assert!(rendered.contains("\nRisks:\n - selectivity unknown\n"));
        assert!(rendered.contains("\nSuggestions:\n - add an index on orders.customer_id\n"));
    }

    #[test]
    fn render_explanation_omits_empty_sections() {
        let parsed = SqlExplanation {
            summary: "Simple query".to_string(),
            tables: vec![],
            joins: vec![],
            filters: vec![],
            risks: vec![],
            suggestions: vec![],
        };

        let rendered = render_explanation(&parsed);

        assert!(rendered.contains("Summary:\nSimple query"));
        assert!(!rendered.contains("Tables:"));
        assert!(!rendered.contains("Joins:"));
        assert!(!rendered.contains("Filters:"));
        assert!(!rendered.contains("Risks:"));
        assert!(!rendered.contains("Suggestions:"));
    }
}
