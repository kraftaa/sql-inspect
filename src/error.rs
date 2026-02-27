use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("missing required environment variable: {0}")]
    MissingEnv(&'static str),

    #[error("provider error: {0}")]
    Provider(String),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}
