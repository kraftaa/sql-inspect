use crate::prompt::{Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisOptions {
    pub suggest_limit_for_exploratory: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            suggest_limit_for_exploratory: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticAnalysis {
    pub findings: Vec<Finding>,
    pub anti_patterns: Vec<String>,
    pub risks: Vec<String>,
    pub suggestions: Vec<String>,
    pub estimated_cost_impact: String,
}

pub fn analyze_sql(sql: &str, options: AnalysisOptions) -> StaticAnalysis {
    let normalized = sql.to_ascii_lowercase();
    let join_count = normalized.matches(" join ").count();
    let tokens: Vec<&str> = normalized.split_whitespace().collect();
    let mut findings = Vec::new();
    let mut anti_patterns = Vec::new();
    let mut risks = Vec::new();
    let mut suggestions = Vec::new();
    let mut score = 0;

    if normalized.contains("select *") {
        findings.push(Finding {
            rule_id: "SELECT_STAR".to_string(),
            severity: Severity::High,
            message: "SELECT *".to_string(),
            why_it_matters: "Select star reads unnecessary columns and usually increases scan cost"
                .to_string(),
            evidence: vec!["SELECT *".to_string()],
        });
        anti_patterns.push("SELECT *".to_string());
        risks.push("SELECT * can scan unnecessary columns and increase cost".to_string());
        suggestions.push("Project only the columns you need".to_string());
        score += 2;
    }

    if join_count >= 3 {
        findings.push(Finding {
            rule_id: "WIDE_JOIN_GRAPH".to_string(),
            severity: Severity::High,
            message: format!("{join_count} joins"),
            why_it_matters: "Wide join graphs can create very large intermediate datasets"
                .to_string(),
            evidence: vec![format!("{join_count} joins detected")],
        });
        anti_patterns.push(format!("{join_count} joins"));
        risks.push("Multiple joins can create large intermediate datasets".to_string());
        suggestions
            .push("Validate join cardinality and pre-aggregate before wide joins".to_string());
        score += 2;
    } else if join_count >= 2 {
        findings.push(Finding {
            rule_id: "MULTIPLE_JOINS".to_string(),
            severity: Severity::Medium,
            message: "Multiple joins".to_string(),
            why_it_matters: "Several joins can increase scan cost and shuffle volume".to_string(),
            evidence: vec![format!("{join_count} joins detected")],
        });
        anti_patterns.push("Multiple joins".to_string());
        risks.push("Several joins can increase scan cost and shuffle volume".to_string());
        suggestions
            .push("Confirm each join is necessary and backed by selective predicates".to_string());
        score += 1;
    }

    if normalized.contains(" like '%") {
        findings.push(Finding {
            rule_id: "LEADING_WILDCARD_LIKE".to_string(),
            severity: Severity::Medium,
            message: "Leading wildcard LIKE".to_string(),
            why_it_matters: "Leading wildcard predicates are hard to prune efficiently".to_string(),
            evidence: vec!["LIKE '%...'".to_string()],
        });
        anti_patterns.push("Leading wildcard LIKE".to_string());
        risks.push("Leading wildcard LIKE predicates often prevent efficient pruning".to_string());
        suggestions
            .push("Avoid leading wildcards or use a search-specific index/system".to_string());
        score += 2;
    }

    if !tokens.contains(&"where") {
        findings.push(Finding {
            rule_id: "MISSING_WHERE".to_string(),
            severity: Severity::Medium,
            message: "No WHERE clause".to_string(),
            why_it_matters: "Queries without selective predicates may scan entire tables"
                .to_string(),
            evidence: vec!["No WHERE clause detected".to_string()],
        });
        anti_patterns.push("No WHERE clause".to_string());
        risks.push("No WHERE clause may trigger a full table scan".to_string());
        suggestions
            .push("Add selective predicates or a partition filter when possible".to_string());
        score += 2;
    }

    if options.suggest_limit_for_exploratory
        && looks_exploratory_select(&tokens, join_count)
        && !tokens.contains(&"limit")
    {
        suggestions.push("Consider adding a LIMIT during ad hoc exploration".to_string());
    }

    if normalized.contains("cross join") {
        findings.push(Finding {
            rule_id: "CROSS_JOIN".to_string(),
            severity: Severity::High,
            message: "CROSS JOIN".to_string(),
            why_it_matters: "Cartesian joins can explode row counts and query cost".to_string(),
            evidence: vec!["CROSS JOIN".to_string()],
        });
        anti_patterns.push("CROSS JOIN".to_string());
        risks.push("CROSS JOIN can explode row counts and query cost".to_string());
        suggestions.push(
            "Replace CROSS JOIN with keyed joins unless a Cartesian product is intentional"
                .to_string(),
        );
        score += 3;
    }

    let estimated_cost_impact = match score {
        0..=1 => "low",
        2..=4 => "medium",
        _ => "high",
    }
    .to_string();

    StaticAnalysis {
        findings,
        anti_patterns,
        risks,
        suggestions,
        estimated_cost_impact,
    }
}

fn looks_exploratory_select(tokens: &[&str], join_count: usize) -> bool {
    matches!(tokens.first(), Some(&"select"))
        && join_count == 0
        && !contains_sequence(tokens, &["group", "by"])
        && !contains_sequence(tokens, &["order", "by"])
        && !tokens.contains(&"union")
        && !tokens.contains(&"with")
        && !tokens.contains(&"insert")
        && !tokens.contains(&"create")
        && !tokens.contains(&"merge")
        && !tokens.contains(&"update")
        && !tokens.contains(&"delete")
}

fn contains_sequence(tokens: &[&str], pattern: &[&str]) -> bool {
    tokens.windows(pattern.len()).any(|window| window == pattern)
}

#[cfg(test)]
mod tests {
    use super::analyze_sql;
    use super::AnalysisOptions;

    #[test]
    fn detects_common_sql_anti_patterns() {
        let sql = "SELECT * FROM orders o JOIN customers c ON o.customer_id = c.id JOIN regions r ON c.region_id = r.id WHERE c.email LIKE '%@example.com'";
        let analysis = analyze_sql(sql, AnalysisOptions::default());

        assert!(analysis.anti_patterns.iter().any(|x| x == "SELECT *"));
        assert!(analysis.anti_patterns.iter().any(|x| x == "Multiple joins"));
        assert!(analysis
            .anti_patterns
            .iter()
            .any(|x| x == "Leading wildcard LIKE"));
        assert_eq!(analysis.estimated_cost_impact, "high");
    }

    #[test]
    fn identifies_low_risk_query() {
        let sql = "SELECT id, created_at FROM orders WHERE created_at >= CURRENT_DATE - INTERVAL '7 days' LIMIT 100";
        let analysis = analyze_sql(sql, AnalysisOptions::default());

        assert!(analysis.anti_patterns.is_empty());
        assert_eq!(analysis.estimated_cost_impact, "low");
    }

    #[test]
    fn missing_limit_is_only_a_soft_suggestion() {
        let sql = "SELECT id, created_at FROM orders WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'";
        let analysis = analyze_sql(sql, AnalysisOptions::default());

        assert!(!analysis.anti_patterns.iter().any(|x| x == "No LIMIT"));
        assert!(analysis
            .suggestions
            .iter()
            .any(|x| x == "Consider adding a LIMIT during ad hoc exploration"));
        assert_eq!(analysis.estimated_cost_impact, "low");
    }

    #[test]
    fn missing_limit_is_not_suggested_for_more_analytical_queries() {
        let sql = "SELECT o.id, c.email FROM orders o JOIN customers c ON o.customer_id = c.id ORDER BY o.created_at DESC";
        let analysis = analyze_sql(sql, AnalysisOptions::default());

        assert!(!analysis
            .suggestions
            .iter()
            .any(|x| x == "Consider adding a LIMIT during ad hoc exploration"));
    }

    #[test]
    fn limit_hint_can_be_disabled() {
        let sql = "SELECT id FROM orders";
        let analysis = analyze_sql(
            sql,
            AnalysisOptions {
                suggest_limit_for_exploratory: false,
            },
        );

        assert!(!analysis
            .suggestions
            .iter()
            .any(|x| x == "Consider adding a LIMIT during ad hoc exploration"));
    }

    #[test]
    fn where_detection_handles_newlines() {
        let sql = "SELECT id\nFROM orders\nWHERE created_at >= CURRENT_DATE - INTERVAL '7 days'";
        let analysis = analyze_sql(sql, AnalysisOptions::default());

        assert!(!analysis.findings.iter().any(|f| f.rule_id == "MISSING_WHERE"));
    }
}
