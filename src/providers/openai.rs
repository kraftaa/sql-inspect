use crate::error::AppError;
use crate::providers::LlmProvider;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::json;

pub struct OpenAIProvider {
    client: reqwest::Client,
    api_key: String,
    model: String,
}

impl OpenAIProvider {
    pub fn new(api_key: String, model: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            model,
        }
    }
}

fn extract_openai_text(v: &serde_json::Value) -> Result<String, AppError> {
    v["output_text"]
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| {
            v["output"].as_array().and_then(|arr| {
                arr.iter().find_map(|item| {
                    item["content"].as_array().and_then(|carr| {
                        carr.iter()
                            .find_map(|c| c["text"].as_str().map(|s| s.to_string()))
                    })
                })
            })
        })
        .ok_or_else(|| AppError::Provider(format!("Unexpected OpenAI response shape: {v}")))
}

#[async_trait::async_trait]
impl LlmProvider for OpenAIProvider {
    async fn explain_sql_json(&self, prompt: &str) -> Result<String, AppError> {
        let body = json!({
            "model": self.model,
            "input": prompt,
            "text": {
                "format": { "type": "json_object" }
            }
        });

        let resp = self
            .client
            .post("https://api.openai.com/v1/responses")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Provider(format!("OpenAI request failed: {e}")))?;

        let status = resp.status();
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Provider(format!("OpenAI JSON parse failed: {e}")))?;

        if !status.is_success() {
            return Err(AppError::Provider(format!(
                "OpenAI error status={status}, body={v}"
            )));
        }

        extract_openai_text(&v)
    }
}

#[cfg(test)]
mod tests {
    use super::extract_openai_text;
    use serde_json::json;

    #[test]
    fn extracts_output_text_when_present() {
        let payload = json!({
            "output_text": r#"{"summary":"ok","tables":[],"joins":[],"filters":[],"risks":[],"suggestions":[]}"#
        });

        let text = extract_openai_text(&payload).expect("should extract output_text");
        assert!(text.contains(r#""summary":"ok""#));
    }

    #[test]
    fn extracts_nested_content_text_when_output_text_missing() {
        let payload = json!({
            "output": [
                {
                    "content": [
                        {
                            "type": "output_text",
                            "text": r#"{"summary":"nested","tables":[],"joins":[],"filters":[],"risks":[],"suggestions":[]}"#
                        }
                    ]
                }
            ]
        });

        let text = extract_openai_text(&payload).expect("should extract nested text");
        assert!(text.contains(r#""summary":"nested""#));
    }

    #[test]
    fn rejects_unexpected_shape() {
        let payload = json!({ "foo": "bar" });
        let err = extract_openai_text(&payload).expect_err("unexpected shape should fail");
        assert!(err.to_string().contains("Unexpected OpenAI response shape"));
    }
}
