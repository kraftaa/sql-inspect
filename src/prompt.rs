use serde::{Deserialize, Serialize};

fn unknown_string() -> String {
    "unknown".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    #[default]
    Unknown,
}

impl Severity {
    pub fn rank(&self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Finding {
    pub rule_id: String,
    #[serde(default)]
    pub severity: Severity,
    pub message: String,
    pub why_it_matters: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SqlExplanation {
    pub summary: String,
    #[serde(default)]
    pub tables: Vec<String>,
    #[serde(default)]
    pub joins: Vec<String>,
    #[serde(default)]
    pub filters: Vec<String>,
    #[serde(default)]
    pub risks: Vec<String>,
    #[serde(default)]
    pub suggestions: Vec<String>,
    #[serde(default)]
    pub anti_patterns: Vec<String>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default = "unknown_string")]
    pub estimated_cost_impact: String,
    #[serde(default = "unknown_string")]
    pub confidence: String,
}

pub fn build_prompt(sql: &str) -> String {
    format!(
        r#"You are a SQL reviewer. ONLY use the SQL text provided. If something is unknown, write "unknown".
Return STRICT JSON with keys:
summary (string), tables (array), joins (array), filters (array), risks (array), suggestions (array),
anti_patterns (array), findings (array of objects with rule_id, severity, message, why_it_matters, evidence),
estimated_cost_impact (string: low|medium|high|unknown), confidence (string: low|medium|high|unknown).

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
    use super::{build_prompt, parse_sql_explanation, Severity};

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
            "suggestions":["Project only needed columns"],
            "anti_patterns":["SELECT *"],
            "findings":[
                {
                    "rule_id":"SELECT_STAR",
                    "severity":"high",
                    "message":"SELECT *",
                    "why_it_matters":"Select star can scan unnecessary columns",
                    "evidence":["SELECT *"]
                }
            ],
            "estimated_cost_impact":"medium",
            "confidence":"high"
        }"#;

        let parsed = parse_sql_explanation(raw).expect("valid JSON should parse");
        assert_eq!(parsed.summary, "Finds recent orders");
        assert_eq!(parsed.tables, vec!["orders"]);
        assert_eq!(parsed.suggestions, vec!["Project only needed columns"]);
        assert_eq!(parsed.anti_patterns, vec!["SELECT *"]);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].rule_id, "SELECT_STAR");
        assert_eq!(parsed.findings[0].severity, Severity::High);
        assert_eq!(parsed.estimated_cost_impact, "medium");
        assert_eq!(parsed.confidence, "high");
    }

    #[test]
    fn parse_sql_explanation_defaults_new_fields_for_older_payloads() {
        let raw = r#"{
            "summary":"Legacy payload",
            "tables":[],
            "joins":[],
            "filters":[],
            "risks":[],
            "suggestions":[]
        }"#;

        let parsed = parse_sql_explanation(raw).expect("legacy JSON should still parse");
        assert!(parsed.anti_patterns.is_empty());
        assert!(parsed.findings.is_empty());
        assert_eq!(parsed.estimated_cost_impact, "unknown");
        assert_eq!(parsed.confidence, "unknown");
    }

    #[test]
    fn parse_sql_explanation_rejects_invalid_json() {
        let err = parse_sql_explanation("not json").expect_err("invalid JSON should fail");
        assert!(err.to_string().contains("Model did not return valid JSON"));
    }
}
