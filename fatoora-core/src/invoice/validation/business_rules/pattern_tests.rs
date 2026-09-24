use super::{FailureKind, patterns::matches};

#[test]
fn xpath_patterns_preserve_search_anchors_backreferences_and_empty_captures() {
    for (input, pattern, expected) in [
        ("SAR", "S", true),
        ("SAR", "^AR", false),
        ("SAR", "AR$", true),
        ("SARSAR", r"^(SAR)\1$", true),
        ("SARSAR2", r"(SAR)\12$", true),
        ("B", r"^(A)?\1B$", true),
        ("AB", r"^(A)?\1B$", false),
        ("SAR", "", true),
        ("SAR\n", "SAR$", false),
        ("\r", ".", false),
        ("SAR", "(?:S|U)AR", true),
    ] {
        assert_eq!(
            matches(input, pattern),
            Ok(expected),
            "{input:?} / {pattern}"
        );
    }
}
#[test]
fn xml_character_classes_use_xml_whitespace_words_names_and_subtraction() {
    for (input, pattern, expected) in [
        (" ", r"\s", true),
        ("\u{a0}", r"\s", false),
        ("\u{a0}", r"\S", true),
        ("١", r"\d", true),
        ("_", r"\w", false),
        ("😀", r"\w", true),
        ("_", r"\W", true),
        ("a:b", r"^\i\c*$", true),
        ("1abc", r"^\i\c*$", false),
        ("SAR", r"^[A-Z-[AEIOU]]+$", false),
        ("SR", r"^[A-Z-[AEIOU]]+$", true),
        ("&", r"^[a&&b]$", true),
        ("a", r"^[a&&b]$", true),
        ("S", r"\p{IsBasicLatin}", true),
        ("ع", r"\p{IsBasicLatin}", false),
        ("ع", r"\p{IsArabic}", true),
        ("S", r"\P{IsArabic}", true),
        ("S", r"\p{Cs}", false),
        ("S", r"\P{Cs}", true),
        ("S", r"\p{IsHighSurrogates}", false),
        ("ع", r"[\p{L}-[A-Z]]", true),
    ] {
        assert_eq!(
            matches(input, pattern),
            Ok(expected),
            "{input:?} / {pattern}"
        );
    }
}
#[test]
fn invalid_patterns_are_errors_and_resource_limits_are_distinct() {
    for pattern in [
        "[",
        "(",
        r"\1",
        r"(\1)",
        r"\b",
        "(?i)SAR",
        "(?=SAR)",
        r"\p{Script=Arabic}",
        r"\p{IsUnknownBlock}",
        "[a-[b]c]",
        "S++",
        "S?+",
        "S{2}+",
    ] {
        assert_eq!(
            matches("SAR", pattern),
            Err(FailureKind::InvalidRegex),
            "{pattern}"
        );
    }
    assert_eq!(
        matches("SAR", &"x".repeat(4097)),
        Err(FailureKind::Limit("regex bytes"))
    );
    assert_eq!(
        matches(&"S".repeat(4097), "S"),
        Err(FailureKind::Limit("regex bytes"))
    );
    assert_eq!(
        matches("S", &format!("{}S{}", "(".repeat(129), ")".repeat(129))),
        Err(FailureKind::Limit("regex depth"))
    );
}

#[test]
fn repeated_patterns_reuse_the_bounded_invoice_cache() {
    let cache = super::patterns::MatchCache::default();
    for _ in 0..1000 {
        assert_eq!(cache.matches("SAR", "^S"), Ok(true));
    }
    for n in 0..127 {
        assert_eq!(cache.matches("SAR", &format!("^{n}")), Ok(false));
    }
    assert_eq!(
        cache.matches("SAR", "^new"),
        Err(FailureKind::Limit("regex patterns"))
    );
    assert_eq!(cache.matches("SAR", "^S"), Ok(true));
    assert_eq!(cache.matches("SAR", "SAR"), Ok(true));
}
