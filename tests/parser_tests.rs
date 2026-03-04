use definatype_engine::parser;

#[test]
fn test_parse_empty_schema() {
    let input = r#"{"models":[]}"#;
    let ast = parser::parse(input).unwrap();
    assert!(ast.models.is_empty());
}

#[test]
fn test_parse_basic_model() {
    let input = include_str!("fixtures/basic_blog.json");
    let ast = parser::parse(input).unwrap();
    assert!(!ast.models.is_empty());
}
