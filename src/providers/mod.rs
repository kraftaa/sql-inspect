use crate::error::AppError;

#[derive(Clone, Debug)]
pub enum ProviderKind {
    OpenAI,
    Bedrock,
}

#[async_trait::async_trait]
pub trait LlmProvider: Send + Sync {
    async fn explain_sql_json(&self, prompt: &str) -> Result<String, AppError>;
}

pub mod bedrock;
pub mod openai;
