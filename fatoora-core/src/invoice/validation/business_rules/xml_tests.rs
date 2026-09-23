use super::{
    FailureKind, Limits,
    xml::{CBC, XmlView, normalize_space},
};

#[test]
fn xml_view_preserves_duplicates_namespaces_text_and_attributes() {
    let xml = format!(
        r#"<r xmlns:a="{CBC}" xmlns:b="{CBC}" xmlns:x="urn:other"><a:Amount currencyID="SAR" x:currencyID="USD"> 1.000&#x20;</a:Amount><b:Amount><![CDATA[2.00]]></b:Amount><x:Amount>3</x:Amount><a:Empty/><a:Mixed>A<x:part>B</x:part>C</a:Mixed></r>"#
    );
    let view = XmlView::parse(&xml, &Limits::default()).unwrap();
    let amounts = view.children(0, CBC, "Amount");
    assert_eq!(amounts.len(), 2);
    assert_eq!(view.node(amounts[0]).text, " 1.000 ");
    assert_eq!(view.node(amounts[1]).text, "2.00");
    assert_eq!(view.attribute(amounts[0], "", "currencyID"), Some("SAR"));
    assert_eq!(
        view.attribute(amounts[0], "urn:other", "currencyID"),
        Some("USD")
    );
    assert!(view.children(0, CBC, "Absent").is_empty());
    assert_eq!(view.node(view.children(0, CBC, "Empty")[0]).text, "");
    assert_eq!(view.node(view.children(0, CBC, "Mixed")[0]).text, "ABC");
    assert!(view.node(amounts[0]).location.ends_with("][1]"));
    assert!(view.node(amounts[1]).location.ends_with("][2]"));
    let renamed = xml
        .replace("<a:", "<z:")
        .replace("</a:", "</z:")
        .replace("xmlns:a=", "xmlns:z=");
    let renamed = XmlView::parse(&renamed, &Limits::default()).unwrap();
    assert_eq!(
        view.node(amounts[1]).location,
        renamed.node(amounts[1]).location
    );
    assert_eq!(normalize_space(" \tSAR\r\n "), "SAR");
    assert_eq!(normalize_space("\u{a0}SAR\u{a0}"), "\u{a0}SAR\u{a0}");
}

#[test]
fn parser_rejects_malformed_xml_and_external_resources() {
    for xml in [
        "<r>",
        "<r/><s/>",
        "<r><a></r>",
        "<r a='1' a='2'/>",
        "<r><unknown:node/></r>",
        "<r>&missing;</r>",
        "<r>&#0;</r>",
    ] {
        assert!(XmlView::parse(xml, &Limits::default()).is_err(), "{xml}");
    }
    for xml in [
        r#"<!DOCTYPE r SYSTEM "file:///etc/passwd"><r/>"#,
        r#"<!DOCTYPE r [<!ENTITY a "expanded">]><r>&a;</r>"#,
    ] {
        assert!(matches!(
            XmlView::parse(xml, &Limits::default()),
            Err(FailureKind::UnsupportedXml(_))
        ));
    }
    let literal = "<r><!-- <!DOCTYPE fake> --><![CDATA[<!DOCTYPE fake>]]></r>";
    assert!(XmlView::parse(literal, &Limits::default()).is_ok());
}

#[test]
fn parser_enforces_input_depth_node_and_materialization_limits() {
    let limits = Limits {
        xml_bytes: 3,
        ..Limits::default()
    };
    assert!(matches!(
        XmlView::parse("<r/>", &limits),
        Err(FailureKind::Limit(_))
    ));
    let limits = Limits {
        depth: 2,
        ..Limits::default()
    };
    assert!(XmlView::parse("<r><a/></r>", &limits).is_ok());
    assert!(matches!(
        XmlView::parse("<r><a><b/></a></r>", &limits),
        Err(FailureKind::Limit(_))
    ));
    let limits = Limits {
        nodes: 2,
        ..Limits::default()
    };
    assert!(matches!(
        XmlView::parse("<r><a/><b/></r>", &limits),
        Err(FailureKind::Limit(_))
    ));
    let limits = Limits {
        retained_bytes: 2,
        ..Limits::default()
    };
    assert!(matches!(
        XmlView::parse("<r>abc</r>", &limits),
        Err(FailureKind::Limit(_))
    ));
}

#[test]
fn locations_resolve_to_original_nodes_with_namespace_aliases_and_quotes() {
    let input = r#"<r xmlns:a="urn:a'&quot;b" xmlns:b="urn:a'&quot;b"><a:n>first</a:n><b:n>second</b:n><n>third</n></r>"#;
    let view = XmlView::parse(input, &Limits::default()).unwrap();
    let document = libxml::parser::Parser::default()
        .parse_string(input)
        .unwrap();
    let xpath = libxml::xpath::Context::new(&document).unwrap();
    for id in view.node(0).children.iter().copied() {
        let nodes = xpath
            .evaluate(&view.node(id).location)
            .unwrap()
            .get_nodes_as_vec();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].get_content(), view.node(id).text);
    }
    for input in [
        r#"<r xmlns:a="urn:a" xmlns:b="urn:a" a:x="1" b:x="2"/>"#,
        r#"<r unknown:a="1"/>"#,
        r#"<?xml version="1.0" encoding="ISO-8859-1"?><r/>"#,
    ] {
        assert!(
            XmlView::parse(input, &Limits::default()).is_err(),
            "{input}"
        );
    }
    let view = XmlView::parse(
        "<?xml version='1.0' encoding='UTF-8'?><r>عربي 💰\u{a0}</r>",
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(view.node(0).text, "عربي 💰\u{a0}");
}

#[test]
fn direct_text_retains_xdm_text_boundaries_and_coalesces_cdata() {
    for (input, expected) in [
        ("<r>10</r>", vec!["10"]),
        ("<r>1<!-- separator -->0</r>", vec!["1", "0"]),
        ("<r>1<?separator value?>0</r>", vec!["1", "0"]),
        ("<r>1<empty/>0</r>", vec!["1", "0"]),
        ("<r>1<![CDATA[0]]>2<![CDATA[3]]></r>", vec!["1023"]),
        ("<r><![CDATA[1]]><![CDATA[0]]></r>", vec!["10"]),
        ("<r>1&#48;&amp;<![CDATA[2]]></r>", vec!["10&2"]),
        ("<r><![CDATA[]]>0<![CDATA[]]></r>", vec!["0"]),
        ("<r/>", vec![]),
        ("<r></r>", vec![]),
        ("<r><![CDATA[]]></r>", vec![]),
        ("<r><!-- comment --><?empty?><child/></r>", vec![]),
        ("<r> <![CDATA[\t]]></r>", vec![" \t"]),
    ] {
        let view = XmlView::parse(input, &Limits::default()).unwrap();
        assert_eq!(view.node(0).direct_text, expected, "{input}");
    }
    let view = XmlView::parse("<r>1<!-- separator -->0</r>", &Limits::default()).unwrap();
    assert_ne!(view.node(0).text, "0");
    assert!(view.node(0).direct_text.iter().any(|text| text == "0"));
}

#[test]
fn direct_text_excludes_descendants_without_changing_element_string_values() {
    let view = XmlView::parse(
        "<r>A<child>B<inner>C</inner>D</child>E<!-- boundary -->F</r>",
        &Limits::default(),
    )
    .unwrap();
    let child = view.children(0, "", "child")[0];
    let inner = view.children(child, "", "inner")[0];
    assert_eq!(view.node(0).direct_text, ["A", "E", "F"]);
    assert_eq!(view.node(child).direct_text, ["B", "D"]);
    assert_eq!(view.node(inner).direct_text, ["C"]);
    assert_eq!(view.node(0).text, "ABCDEF");
    assert_eq!(view.node(child).text, "BCD");
    assert_eq!(view.node(inner).text, "C");
}

#[test]
fn direct_text_counts_utf8_bytes_toward_retained_limit() {
    let input = "<r>ع<!-- split -->💰</r>";
    let view = XmlView::parse(input, &Limits::default()).unwrap();
    let root = view.node(0);
    let previous_bytes =
        root.name.len() + root.namespace.len() + root.location.len() + root.text.len();
    let retained_bytes = previous_bytes + "ع".len() + "💰".len();
    for limit in [previous_bytes, retained_bytes - 1] {
        let limits = Limits {
            retained_bytes: limit,
            ..Limits::default()
        };
        assert!(matches!(
            XmlView::parse(input, &limits),
            Err(FailureKind::Limit("XML retained bytes"))
        ));
    }
    let limits = Limits {
        retained_bytes,
        ..Limits::default()
    };
    let view = XmlView::parse(input, &limits).unwrap();
    assert_eq!(view.node(0).direct_text, ["ع", "💰"]);
}
