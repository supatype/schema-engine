use supatype_engine::generator::sql::storage;
use supatype_engine::parser;

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

#[test]
fn test_storage_buckets_merge_and_declarative_rls() {
    let input = r#"{
        "storageBuckets": [{
            "id": "docs",
            "public": false,
            "accessMode": "private",
            "allowedMimeTypes": ["application/pdf"],
            "fileSizeLimit": 52428800,
            "access": {
                "read": { "type": "public" },
                "create": { "type": "authenticated" },
                "delete": { "type": "authenticated" }
            }
        }],
        "models": [{
            "name": "Post", "tableName": "posts",
            "fields": {
                "id": { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } },
                "manual": { "kind": "file", "pgType": "TEXT", "required": false, "bucket": "docs" }
            },
            "access": { "read": { "type": "authenticated" } },
            "indexes": [], "options": { "timestamps": false, "softDelete": false }
        }]
    }"#;

    let ast = parser::parse(input).unwrap();
    let b = ast.storage_buckets.iter().find(|x| x.id == "docs").expect("docs bucket");
    assert_eq!(b.allowed_mime_types.as_ref().map(|v| v.as_slice()), Some(&["application/pdf".to_string()][..]));
    assert_eq!(b.file_size_limit, Some(52428800));
    assert!(b.access.is_some());

    let sql = storage::generate(&ast).unwrap();
    assert!(sql.contains("storage_docs_sel"));
    assert!(
        !sql.contains("posts_docs_sel"),
        "declarative bucket RLS should suppress model/table-prefixed policies for that bucket"
    );
}
