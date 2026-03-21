use crate::error::AppError;

#[async_trait::async_trait]
pub trait LlmProvider: Send + Sync {
    async fn explain_sql_json(&self, prompt: &str) -> Result<String, AppError>;
}

#[cfg(feature = "bedrock")]
pub mod bedrock;
pub mod local;
pub mod openai;
