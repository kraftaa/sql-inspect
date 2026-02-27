use crate::error::AppError;
use crate::providers::LlmProvider;
use aws_config::BehaviorVersion;
use aws_sdk_bedrockruntime::primitives::Blob;

pub struct BedrockProvider {
    client: aws_sdk_bedrockruntime::Client,
    model_id: String,
}

impl BedrockProvider {
    pub async fn new(model_id: String) -> Result<Self, AppError> {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let client = aws_sdk_bedrockruntime::Client::new(&config);
        Ok(Self { client, model_id })
    }
}

fn extract_bedrock_text(v: &serde_json::Value) -> Result<String, AppError> {
    v["content"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|c0| c0["text"].as_str())
        .map(|s| s.to_string())
        .or_else(|| v["output_text"].as_str().map(|s| s.to_string()))
        .ok_or_else(|| AppError::Provider(format!("Unexpected Bedrock response shape: {v}")))
}

#[async_trait::async_trait]
impl LlmProvider for BedrockProvider {
    async fn explain_sql_json(&self, prompt: &str) -> Result<String, AppError> {
        let body_json = serde_json::json!({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 800,
            "temperature": 0.2,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        { "type": "text", "text": prompt }
                    ]
                }
            ]
        });

        let bytes =
            serde_json::to_vec(&body_json).map_err(|e| AppError::Provider(e.to_string()))?;

        let resp = self
            .client
            .invoke_model()
            .model_id(&self.model_id)
            .content_type("application/json")
            .accept("application/json")
            .body(Blob::new(bytes))
            .send()
            .await
            .map_err(|e| AppError::Provider(format!("Bedrock invoke_model failed: {e}")))?;

        let out = resp.body().as_ref();
        let v: serde_json::Value = serde_json::from_slice(out)
            .map_err(|e| AppError::Provider(format!("Bedrock JSON parse failed: {e}")))?;

        extract_bedrock_text(&v)
    }
}

#[cfg(test)]
mod tests {
    use super::extract_bedrock_text;
    use serde_json::json;

    #[test]
    fn extracts_claude_content_text() {
        let payload = json!({
            "content": [
                {
                    "type": "text",
                    "text": r#"{"summary":"claude","tables":[],"joins":[],"filters":[],"risks":[],"suggestions":[]}"#
                }
            ]
        });

        let text = extract_bedrock_text(&payload).expect("should extract Claude content");
        assert!(text.contains(r#""summary":"claude""#));
    }

    #[test]
    fn extracts_output_text_fallback() {
        let payload = json!({
            "output_text": r#"{"summary":"fallback","tables":[],"joins":[],"filters":[],"risks":[],"suggestions":[]}"#
        });

        let text = extract_bedrock_text(&payload).expect("should extract output_text");
        assert!(text.contains(r#""summary":"fallback""#));
    }

    #[test]
    fn rejects_unexpected_shape() {
        let payload = json!({ "foo": "bar" });
        let err = extract_bedrock_text(&payload).expect_err("unexpected shape should fail");
        assert!(err
            .to_string()
            .contains("Unexpected Bedrock response shape"));
    }
}
