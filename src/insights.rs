#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageItem {
    pub output: String,
    pub expression: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryExplanation {
    pub purpose: String,
    pub tables: Vec<String>,
    pub aggregations: Vec<String>,
}

pub fn extract_tables(sql: &str) -> Vec<String> {
    let normalized = sql.to_ascii_lowercase();
    let tokens: Vec<&str> = normalized.split_whitespace().collect();
    let mut tables = Vec::new();

    let mut i = 0;
    while i + 1 < tokens.len() {
        let token = tokens[i];
        if token == "from" || token == "join" {
            let candidate =
                tokens[i + 1].trim_matches(|c: char| c == ',' || c == ';' || c == '(' || c == ')');
            if !candidate.is_empty()
                && candidate != "select"
                && candidate != "("
                && !tables.iter().any(|t| t == candidate)
            {
                tables.push(candidate.to_string());
            }
        }
        i += 1;
    }

    tables
}

pub fn extract_lineage(sql: &str) -> Vec<LineageItem> {
    let lower = sql.to_ascii_lowercase();
    let Some(select_pos) = lower.find("select") else {
        return Vec::new();
    };
    let Some(from_pos) = lower[select_pos..].find("from").map(|p| p + select_pos) else {
        return Vec::new();
    };

    let select_clause = &sql[select_pos + 6..from_pos];
    let parts = split_top_level(select_clause, ',');
    let mut items = Vec::new();

    for part in parts {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (output, expression) = parse_select_item(trimmed);
        items.push(LineageItem { output, expression });
    }

    items
}

pub fn explain_query(sql: &str) -> QueryExplanation {
    let tables = extract_tables(sql);
    let lower = sql.to_ascii_lowercase();
    let mut aggregations = Vec::new();

    for agg in ["sum(", "count(", "avg(", "min(", "max("] {
        if lower.contains(agg) {
            aggregations.push(agg.trim_end_matches('(').to_ascii_uppercase());
        }
    }

    let purpose = if !aggregations.is_empty() {
        "calculate aggregate metrics".to_string()
    } else if tables.is_empty() {
        "query data".to_string()
    } else {
        format!("read data from {}", tables.join(", "))
    };

    QueryExplanation {
        purpose,
        tables,
        aggregations,
    }
}

fn split_top_level(input: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut current = String::new();

    for ch in input.chars() {
        match ch {
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            c if c == sep && depth == 0 => {
                out.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }

    out
}

fn parse_select_item(item: &str) -> (String, String) {
    let lower = item.to_ascii_lowercase();
    if let Some(pos) = lower.rfind(" as ") {
        let expr = item[..pos].trim().to_string();
        let output = item[pos + 4..].trim().to_string();
        return (output, expr);
    }

    let words: Vec<&str> = item.split_whitespace().collect();
    if words.len() > 1 {
        let output = words[words.len() - 1].to_string();
        let expr = words[..words.len() - 1].join(" ");
        return (output, expr);
    }

    (item.trim().to_string(), item.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::{explain_query, extract_lineage, extract_tables};

    #[test]
    fn extracts_tables_from_from_and_join() {
        let sql = "SELECT o.id FROM orders o JOIN customers c ON o.customer_id = c.id";
        let tables = extract_tables(sql);
        assert_eq!(tables, vec!["orders", "customers"]);
    }

    #[test]
    fn extracts_basic_lineage() {
        let sql = "SELECT SUM(o.amount) AS revenue, o.customer_id FROM orders o";
        let lineage = extract_lineage(sql);
        assert_eq!(lineage[0].output, "revenue");
        assert_eq!(lineage[0].expression, "SUM(o.amount)");
        assert_eq!(lineage[1].output, "o.customer_id");
    }

    #[test]
    fn explains_query_with_aggregations() {
        let sql = "SELECT SUM(amount) AS revenue FROM orders";
        let explanation = explain_query(sql);
        assert!(explanation.purpose.contains("aggregate"));
        assert_eq!(explanation.tables, vec!["orders"]);
        assert_eq!(explanation.aggregations, vec!["SUM"]);
    }
}
