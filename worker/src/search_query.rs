//! Turns a person's search box into a safe FTS5 query.
//!
//! The result is bound as a parameter. Characters that change FTS syntax are
//! dropped before that happens.

/// Builds an FTS5 `MATCH` string from free text.
///
/// Returns [`None`] when nothing searchable remains, which means "list recent
/// articles" rather than "match everything".
pub fn fts_match(raw: &str) -> Option<String> {
    let tokens: Vec<String> = raw
        .split_whitespace()
        .filter_map(|word| {
            let cleaned: String = word
                .chars()
                .filter(|ch| ch.is_alphanumeric() || *ch == '\'' || *ch == '-')
                .collect();
            if cleaned.chars().count() < 2 {
                None
            } else {
                Some(format!("\"{cleaned}\"*"))
            }
        })
        .take(12)
        .collect();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operators_are_removed_and_words_become_prefixes() {
        assert_eq!(
            fts_match("vacation OR policy"),
            Some("\"vacation\"* \"OR\"* \"policy\"*".to_string())
        );
    }

    #[test]
    fn punctuation_only_input_lists_recent_articles() {
        assert_eq!(fts_match("  * \"\" ( ) "), None);
    }

    #[test]
    fn short_tokens_are_dropped() {
        assert_eq!(
            fts_match("a an onboarding"),
            Some("\"an\"* \"onboarding\"*".to_string())
        );
    }
}
