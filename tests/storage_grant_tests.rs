//! The grant that lets the storage service ask Postgres who may read an object.
//!
//! A bucket's declared read rule becomes an RLS policy on `storage.objects`, and those policies
//! were correct: `read: BucketLoggedIn` produced `auth.uid() IS NOT NULL`, `read: BucketOwner`
//! produced `auth.uid() = owner`. Nothing ever evaluated them.
//!
//! The storage service connects as a superuser, which bypasses RLS, and decided access itself from
//! `access_mode` alone, hardcoding owner-only for every private bucket. So a bucket declaring
//! `BucketLoggedIn` refused every caller but the uploader, and the policy was unreachable. It
//! failed safe, which is why it went unnoticed.
//!
//! Deferring the decision to Postgres means the service switches to the caller's role and selects
//! the row. That is refused before RLS is consulted unless the role holds a SELECT grant, and no
//! role held any grant on this table at all.
//!
//! Granting is only safe because RLS is enabled on the same table, in the same statement block: a
//! bucket with no policy default-denies. The control below asserts the two travel together, since
//! a grant that outlived the ENABLE would publish every object in the project.

use supatype_engine::generator::sql::storage;
use supatype_engine::parser;

fn generated() -> String {
    let src = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "doc",
      "annotations": { "db": { "tableName": "doc" } },
      "fields": {
        "id": { "kind": "uuid", "required": true },
        "file": { "kind": "image", "required": false, "bucket": "shared" }
      }
    }
  ],
  "storageBuckets": [
    {
      "id": "shared",
      "public": false,
      "accessMode": "private",
      "access": { "read": { "type": "authenticated" }, "delete": { "type": "owner", "field": "owner" } }
    }
  ]
}"#;
    let ast = parser::parse(src).expect("schema parses");
    storage::generate(&ast).expect("storage sql generates")
}

#[test]
fn the_caller_roles_can_select_objects() {
    let sql = generated();
    assert!(
        sql.contains("GRANT SELECT ON storage.objects TO anon, authenticated"),
        "without this the service cannot evaluate the policy as the caller, got:\n{sql}"
    );
}

#[test]
fn row_level_security_is_enabled_on_the_same_table() {
    // The control. A grant is only safe while RLS gates the rows it exposes.
    let sql = generated();
    assert!(
        sql.contains("ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;"),
        "granting without RLS would publish every object, got:\n{sql}"
    );
}

#[test]
fn the_grant_never_appears_without_the_enable() {
    // Ordering matters as much as presence: a grant applied before RLS is on leaves a window in
    // which every object is readable by any signed-in caller.
    let sql = generated();
    let enable = sql.find("ENABLE ROW LEVEL SECURITY");
    let grant = sql.find("GRANT SELECT ON storage.objects");
    match (enable, grant) {
        (Some(e), Some(g)) => assert!(e < g, "RLS must be enabled before the grant, got:\n{sql}"),
        (_, None) => panic!("no grant emitted:\n{sql}"),
        (None, _) => panic!("no RLS enable emitted:\n{sql}"),
    }
}
