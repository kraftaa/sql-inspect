use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SqlInspectConfig {
    pub dialect: Option<String>,
    pub fail_on: Option<String>,
    pub glob: Option<String>,
    pub suggest_limit_for_exploratory: Option<bool>,
    pub static_only: Option<bool>,
}

pub fn load_config(path: Option<&Path>) -> anyhow::Result<SqlInspectConfig> {
    let config_path = match path {
        Some(path) => Some(path.to_path_buf()),
        None => {
            let default = PathBuf::from("sql-inspect.toml");
            if default.exists() {
                Some(default)
            } else {
                None
            }
        }
    };

    match config_path {
        Some(path) => {
            let raw = std::fs::read_to_string(&path)?;
            let config: SqlInspectConfig = toml::from_str(&raw)?;
            Ok(config)
        }
        None => Ok(SqlInspectConfig::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::load_config;

    #[test]
    fn missing_default_config_is_ok() {
        let tmp = tempfile_dir();
        let original = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(&tmp).expect("set cwd");

        let config = load_config(None).expect("missing config should be fine");
        assert!(config.fail_on.is_none());

        std::env::set_current_dir(original).expect("restore cwd");
        std::fs::remove_dir_all(tmp).expect("cleanup");
    }

    #[test]
    fn explicit_config_parses() {
        let tmp = tempfile_dir();
        let path = tmp.join("sql-inspect.toml");
        std::fs::write(
            &path,
            "dialect = \"athena\"\nfail_on = \"medium\"\nglob = \"*.sql\"\nsuggest_limit_for_exploratory = false\n",
        )
        .expect("write config");

        let config = load_config(Some(&path)).expect("config should parse");
        assert_eq!(config.dialect.as_deref(), Some("athena"));
        assert_eq!(config.fail_on.as_deref(), Some("medium"));
        assert_eq!(config.glob.as_deref(), Some("*.sql"));
        assert_eq!(config.suggest_limit_for_exploratory, Some(false));

        std::fs::remove_dir_all(tmp).expect("cleanup");
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let base = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("unix time")
            .as_nanos();
        let dir = base.join(format!("sql-inspect-test-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }
}
