use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SqlExplanation {
    pub summary: String,
    pub tables: Vec<String>,
    pub joins: Vec<String>,
    pub filters: Vec<String>,
    pub risks: Vec<String>,
    pub suggestions: Vec<String>,
}

pub fn build_prompt(sql: &str) -> String {
    format!(
        r#"You are a SQL reviewer. ONLY use the SQL text provided. If something is unknown, write "unknown".
Return STRICT JSON with keys:
summary (string), tables (array), joins (array), filters (array), risks (array), suggestions (array).

SQL:
```sql
{sql}
```
"#
    )
}

pub fn parse_sql_explanation(raw_json: &str) -> anyhow::Result<SqlExplanation> {
    serde_json::from_str(raw_json).map_err(|e| {
        anyhow::anyhow!(
            "Model did not return valid JSON. Try --json to inspect. Error: {e}\nRaw:\n{raw_json}"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{build_prompt, parse_sql_explanation};

    #[test]
    fn build_prompt_includes_sql_and_contract() {
        let sql = "select * from orders";
        let prompt = build_prompt(sql);

        assert!(prompt.contains("Return STRICT JSON with keys:"));
        assert!(prompt.contains("summary (string)"));
        assert!(prompt.contains("```sql"));
        assert!(prompt.contains(sql));
    }

    #[test]
    fn parse_sql_explanation_accepts_valid_json() {
        let raw = r#"{
            "summary":"Finds recent orders",
            "tables":["orders"],
            "joins":[],
            "filters":["created_at >= current_date - interval '30 days'"],
            "risks":["select * may read unnecessary columns"],
            "suggestions":["Project only needed columns"]
        }"#;

        let parsed = parse_sql_explanation(raw).expect("valid JSON should parse");
        assert_eq!(parsed.summary, "Finds recent orders");
        assert_eq!(parsed.tables, vec!["orders"]);
        assert_eq!(parsed.suggestions, vec!["Project only needed columns"]);
    }

    #[test]
    fn parse_sql_explanation_rejects_invalid_json() {
        let err = parse_sql_explanation("not json").expect_err("invalid JSON should fail");
        assert!(err.to_string().contains("Model did not return valid JSON"));
    }
}
