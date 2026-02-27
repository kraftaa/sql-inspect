use sql_ai_explainer::error::AppError;
use sql_ai_explainer::prompt::{build_prompt, parse_sql_explanation};
use sql_ai_explainer::providers::LlmProvider;

struct FakeProvider {
    response: String,
}

#[async_trait::async_trait]
impl LlmProvider for FakeProvider {
    async fn explain_sql_json(&self, prompt: &str) -> Result<String, AppError> {
        assert!(prompt.contains("Return STRICT JSON with keys:"));
        assert!(prompt.contains("SELECT id FROM orders"));
        Ok(self.response.clone())
    }
}

#[tokio::test]
async fn fake_provider_returns_json_that_matches_contract() {
    let sql = "SELECT id FROM orders";
    let prompt = build_prompt(sql);
    let provider = FakeProvider {
        response: r#"{
            "summary":"Reads order ids",
            "tables":["orders"],
            "joins":[],
            "filters":[],
            "risks":[],
            "suggestions":["Add a LIMIT for exploratory queries"]
        }"#
        .to_string(),
    };

    let raw_json = provider
        .explain_sql_json(&prompt)
        .await
        .expect("fake provider should return response");

    let parsed = parse_sql_explanation(&raw_json).expect("response should match contract");
    assert_eq!(parsed.summary, "Reads order ids");
    assert_eq!(parsed.tables, vec!["orders"]);
}

#[tokio::test]
async fn fake_provider_exposes_invalid_json_early() {
    let prompt = build_prompt("SELECT id FROM orders");
    let provider = FakeProvider {
        response: "definitely not json".to_string(),
    };

    let raw_json = provider
        .explain_sql_json(&prompt)
        .await
        .expect("fake provider should return response");

    let err = parse_sql_explanation(&raw_json).expect_err("invalid JSON should be rejected");
    assert!(err.to_string().contains("Model did not return valid JSON"));
}
