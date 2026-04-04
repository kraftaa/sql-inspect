use crate::insights::{extract_lineage_report, extract_tables};
use crate::prompt::SqlExplanation;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TableStats {
    pub table_name: Option<String>,
    pub total_bytes: Option<u64>,
    pub row_count: Option<u64>,
    pub partition_columns: Vec<String>,
    pub partitions_per_year: Option<u32>,
    pub column_count: Option<u32>,
    pub format: Option<String>, // parquet, csv, iceberg, orc, etc.
}

pub type StatsMap = HashMap<String, TableStats>;

#[derive(Debug, Serialize)]
pub struct CostEstimate {
    pub file: String,
    pub engine: String,
    pub estimated_scan_bytes: Option<u64>,
    pub estimated_scan_human: String,
    pub estimated_cost_usd: Option<f64>,
    pub risk: String,
    pub confidence: String,
    pub signals: Vec<String>,
}

pub fn load_stats_map(path: &std::path::Path) -> anyhow::Result<StatsMap> {
    let raw = std::fs::read_to_string(path)?;
    let value: serde_json::Value = serde_json::from_str(&raw)?;

    let source = value.get("tables").unwrap_or(&value);
    let map = source.as_object().ok_or_else(|| {
        anyhow::anyhow!("stats JSON must be an object or have a top-level tables object")
    })?;

    let mut out = StatsMap::new();
    for (name, node) in map {
        if let Some(mut stats) = parse_stats_node(node, Some(name.as_str())) {
            if stats.table_name.is_none() {
                stats.table_name = Some(name.clone());
            }
            out.insert(name.clone(), stats);
        }
    }
    Ok(out)
}

pub fn normalize_stats_map_keys(stats_map: &StatsMap) -> StatsMap {
    let mut out = StatsMap::new();
    for (key, value) in stats_map {
        out.insert(normalize_table_key(key), value.clone());
    }
    out
}

pub fn estimate_cost(
    file: &str,
    sql: &str,
    parsed: &SqlExplanation,
    engine: &str,
    stats_map: &StatsMap,
    scan_bytes_override: Option<u64>,
    scan_tb_override: Option<f64>,
) -> CostEstimate {
    let override_used = scan_bytes_override.is_some() || scan_tb_override.is_some();

    // If explicit overrides are provided, use them directly.
    if let Some(bytes) = scan_bytes_override {
        return make_estimate(file, engine, Some(bytes), parsed, Vec::new(), override_used);
    }
    if let Some(tb) = scan_tb_override {
        let bytes = (tb * 1_000_000_000_000_f64) as u64;
        return make_estimate(file, engine, Some(bytes), parsed, Vec::new(), override_used);
    }

    let mut signals = Vec::new();
    for table in extract_tables(sql) {
        if let Some(stats) = stats_map.get(&table) {
            if stats.total_bytes.is_none() {
                signals.push(format!("{table}: missing total_bytes in stats"));
            }
        } else {
            signals.push(format!("{table}: no stats found"));
        }
    }

    let estimated = estimate_scan_from_stats(sql, stats_map);
    if signals.is_empty() {
        signals.push("estimated from stats/heuristics".to_string());
    }
    make_estimate(file, engine, estimated, parsed, signals, override_used)
}

pub fn estimate_scan_from_stats(sql: &str, stats_map: &StatsMap) -> Option<u64> {
    let tables = extract_tables(sql);
    if tables.is_empty() {
        return None;
    }

    let select_star = sql.to_ascii_lowercase().contains("select *");
    let filters = extract_lineage_report(sql).filters;
    let mut total = 0_u64;
    let mut matched = false;

    for table in tables {
        let table_key = normalize_table_key(&table);
        let Some(stats) = stats_map.get(&table_key) else {
            continue;
        };
        let Some(bytes) = stats.total_bytes else {
            continue;
        };

        let partition_factor = estimate_scan_fraction(stats, &filters);
        let column_factor =
            estimate_column_factor(stats.column_count, stats.format.as_deref(), select_star);
        total = total.saturating_add((bytes as f64 * partition_factor * column_factor) as u64);
        matched = true;
    }

    if matched {
        Some(total)
    } else {
        None
    }
}

fn estimate_scan_fraction(stats: &TableStats, filters: &[String]) -> f64 {
    if stats.partition_columns.is_empty() {
        return if filters.is_empty() { 1.0 } else { 0.7 };
    }

    let filters_lower: Vec<String> = filters.iter().map(|f| f.to_ascii_lowercase()).collect();
    let matches_partition = stats
        .partition_columns
        .iter()
        .any(|part| filters_lower.iter().any(|f| f.contains(part)));

    if matches_partition {
        let has_range = filters_lower
            .iter()
            .any(|f| f.contains("between") || f.contains(">") || f.contains("<"));
        if let Some(parts) = stats.partitions_per_year {
            let days = if has_range { 30.0 } else { 1.0 };
            return (days / parts.max(1) as f64).clamp(0.01, 1.0);
        }
        return if has_range { 0.05 } else { 0.02 };
    }

    if filters.is_empty() {
        1.0
    } else {
        0.7
    }
}

fn estimate_column_factor(
    total_columns: Option<u32>,
    format: Option<&str>,
    select_star: bool,
) -> f64 {
    if select_star {
        return 1.0;
    }

    let is_columnar = matches!(format, Some("parquet") | Some("orc") | Some("iceberg"));
    if !is_columnar {
        return 1.0;
    }

    match total_columns {
        Some(total) if total > 0 => 0.5_f64.clamp(0.05, 1.0),
        _ => 0.5,
    }
}

fn athena_cost_usd(bytes: u64) -> f64 {
    const BYTES_PER_TB: f64 = 1024.0 * 1024.0 * 1024.0 * 1024.0;
    (bytes as f64 / BYTES_PER_TB) * 5.0
}

fn make_estimate(
    file: &str,
    engine: &str,
    bytes: Option<u64>,
    parsed: &SqlExplanation,
    mut signals: Vec<String>,
    override_used: bool,
) -> CostEstimate {
    let estimated_scan_human = bytes_to_human_label(bytes);
    let estimated_cost_usd = match (engine.eq_ignore_ascii_case("athena"), bytes) {
        (true, Some(b)) => Some(athena_cost_usd(b)),
        _ => None,
    };
    if signals.is_empty() {
        signals.push("estimated from stats/heuristics".to_string());
    }
    let has_stats_gaps = signals
        .iter()
        .any(|s| s.contains("no stats found") || s.contains("missing total_bytes"));

    CostEstimate {
        file: file.to_string(),
        engine: engine.to_string(),
        estimated_scan_bytes: bytes,
        estimated_scan_human,
        estimated_cost_usd,
        risk: max_risk_label(parsed),
        confidence: match (bytes.is_some(), override_used, has_stats_gaps) {
            (false, _, _) => "low".to_string(),
            (true, true, _) => "high".to_string(),
            (true, false, true) => "low".to_string(),
            (true, false, false) => "medium".to_string(),
        },
        signals,
    }
}

pub fn bytes_to_human_label(bytes: Option<u64>) -> String {
    match bytes {
        Some(bytes) if bytes >= 1_000_000_000_000 => {
            format!("{:.2} TB", bytes as f64 / 1_000_000_000_000_f64)
        }
        Some(bytes) if bytes >= 1_000_000_000 => {
            format!("{:.0} GB", bytes as f64 / 1_000_000_000_f64)
        }
        Some(bytes) if bytes >= 1_000_000 => {
            format!("{:.0} MB", bytes as f64 / 1_000_000_f64)
        }
        Some(bytes) => format!("{bytes} B"),
        None => "unknown".to_string(),
    }
}

fn parse_stats_node(node: &serde_json::Value, table_name: Option<&str>) -> Option<TableStats> {
    let total_bytes = parse_bytes_value(node.get("total_bytes").unwrap_or(node));
    let row_count = node.get("row_count").and_then(parse_u64_value);
    let partition_columns = node
        .get("partition_columns")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let partitions_per_year = node.get("partitions_per_year").and_then(parse_u32_value);
    let column_count = node.get("column_count").and_then(parse_u32_value);
    let format = node
        .get("format")
        .and_then(|v| v.as_str())
        .map(|s| s.to_ascii_lowercase());

    if total_bytes.is_none()
        && row_count.is_none()
        && partition_columns.is_empty()
        && partitions_per_year.is_none()
        && column_count.is_none()
        && format.is_none()
    {
        return None;
    }

    Some(TableStats {
        table_name: table_name.map(std::string::ToString::to_string),
        total_bytes,
        row_count,
        partition_columns,
        partitions_per_year,
        column_count,
        format,
    })
}

fn normalize_table_key(input: &str) -> String {
    input
        .trim()
        .trim_matches('"')
        .trim_matches('`')
        .trim_matches('\'')
        .to_ascii_lowercase()
}

fn parse_u64_value(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse::<u64>().ok()))
}

fn parse_u32_value(value: &serde_json::Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .or_else(|| value.as_str().and_then(|s| s.parse::<u32>().ok()))
}

fn parse_bytes_value(value: &serde_json::Value) -> Option<u64> {
    if let Some(n) = parse_u64_value(value) {
        return Some(n);
    }
    value.get("bytes").and_then(parse_u64_value)
}

fn max_risk_label(parsed: &SqlExplanation) -> String {
    let mut rank = 0_u8;
    for finding in &parsed.findings {
        rank = rank.max(finding.severity.rank());
    }
    match rank {
        3 => "HIGH".to_string(),
        2 => "MEDIUM".to_string(),
        _ => "LOW".to_string(),
    }
}

pub fn collect_postgres_stats(conn: &str) -> anyhow::Result<serde_json::Value> {
    let sql = r#"
SELECT
  quote_ident(relname) || E'\t' || pg_total_relation_size(oid)::text || E'\t' || reltuples::bigint::text
FROM pg_class
WHERE relkind = 'r'
ORDER BY relname;
"#;
    let output = std::process::Command::new("psql")
        .arg(conn)
        .arg("-t")
        .arg("-A")
        .arg("-F")
        .arg(",")
        .arg("-c")
        .arg(sql)
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("psql failed: {stderr}"));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut map = serde_json::Map::new();
    for line in stdout.lines() {
        let mut parts = line.splitn(3, '\t');
        let Some(name_raw) = parts.next() else {
            continue;
        };
        let Some(bytes_raw) = parts.next() else {
            continue;
        };
        let Some(rows_raw) = parts.next() else {
            continue;
        };

        let name = name_raw.trim().trim_matches('"');
        let bytes = bytes_raw.trim().parse::<u64>().ok();
        let rows = rows_raw.trim().parse::<u64>().ok();
        let stats = serde_json::json!({
            "table_name": name,
            "total_bytes": bytes,
            "row_count": rows,
        });
        map.insert(name.to_string(), stats);
    }
    Ok(serde_json::json!({ "tables": map }))
}

#[cfg(test)]
mod tests {
    use super::{
        estimate_cost, estimate_scan_from_stats, load_stats_map, normalize_stats_map_keys,
    };
    use crate::prompt::SqlExplanation;

    #[test]
    fn load_stats_map_accepts_bytes_short_form() {
        let dir = std::env::temp_dir().join("querylens_cost_map_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("stats.json");
        std::fs::write(
            &path,
            r#"{
  "tables": {
    "orders": { "bytes": 1000000000, "partition_columns": ["ds"], "partitions_per_year": 365 },
    "customers": 200000000
  }
}"#,
        )
        .expect("write stats");

        let map = load_stats_map(&path).expect("load stats");
        assert_eq!(
            map.get("orders").and_then(|s| s.total_bytes),
            Some(1_000_000_000)
        );
        assert_eq!(
            map.get("customers").and_then(|s| s.total_bytes),
            Some(200_000_000)
        );

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn estimate_cost_reports_file_label_not_sql() {
        let stats = std::collections::HashMap::new();
        let parsed = SqlExplanation {
            summary: "s".to_string(),
            tables: vec![],
            joins: vec![],
            filters: vec![],
            risks: vec![],
            suggestions: vec![],
            anti_patterns: vec![],
            findings: vec![],
            estimated_cost_impact: "unknown".to_string(),
            confidence: "unknown".to_string(),
        };
        let est = estimate_cost(
            "examples/query.sql",
            "SELECT * FROM orders",
            &parsed,
            "athena",
            &stats,
            Some(1_000_000),
            None,
        );
        assert_eq!(est.file, "examples/query.sql");
    }

    #[test]
    fn estimate_scan_from_stats_uses_partition_pruning_heuristic() {
        let mut stats = std::collections::HashMap::new();
        stats.insert(
            "orders".to_string(),
            super::TableStats {
                total_bytes: Some(1_000_000_000_000),
                partition_columns: vec!["order_date".to_string()],
                partitions_per_year: Some(365),
                ..Default::default()
            },
        );
        let sql = "SELECT order_id FROM orders WHERE order_date >= DATE '2026-01-01'";
        let estimated = estimate_scan_from_stats(sql, &stats).expect("estimate should exist");
        assert!(estimated < 200_000_000_000, "expected partition pruning");
    }

    #[test]
    fn normalize_stats_map_keys_matches_mixed_case_identifiers() {
        let mut stats = std::collections::HashMap::new();
        stats.insert(
            "\"Orders\"".to_string(),
            super::TableStats {
                total_bytes: Some(1_000_000),
                ..Default::default()
            },
        );
        let normalized = normalize_stats_map_keys(&stats);
        let estimated =
            estimate_scan_from_stats("SELECT * FROM orders", &normalized).expect("estimate");
        assert_eq!(estimated, 1_000_000);
    }
}
