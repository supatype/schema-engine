use anyhow::Result;
use crate::parser::ast::{FieldAst, SchemaAst, StorageBucketAst};
use crate::generator::sql::rls::access_rule_to_expr;

/// Generates SQL for the storage subsystem:
///   1. `storage` schema + `storage.buckets` + `storage.objects` DDL (idempotent).
///   2. UPSERT for every bucket inferred from image/file fields.
///   3. RLS policies on `storage.objects` inheriting model access rules.
pub fn generate(ast: &SchemaAst) -> Result<String> {
    if ast.storage_buckets.is_empty() {
        return Ok("-- No storage buckets declared in schema.\n".to_string());
    }

    let mut out = String::new();

    out.push_str(storage_schema_ddl());
    out.push('\n');

    out.push_str("-- ─── Bucket registrations ──────────────────────────────────────────\n\n");
    for bucket in &ast.storage_buckets {
        out.push_str(&bucket_upsert_sql(bucket));
        out.push('\n');
    }

    let rls = generate_storage_rls(ast);
    if !rls.is_empty() {
        out.push_str(&rls);
    }

    Ok(out)
}

/// DDL that sets up the storage schema and tables.
/// Safe to run repeatedly — uses IF NOT EXISTS throughout.
pub fn storage_schema_ddl() -> &'static str {
    r#"-- ─── Storage schema ────────────────────────────────────────────────────────
-- Safe to run repeatedly (IF NOT EXISTS / CREATE OR REPLACE).

CREATE SCHEMA IF NOT EXISTS storage;

CREATE TABLE IF NOT EXISTS storage.buckets (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    public             BOOLEAN NOT NULL DEFAULT false,
    allowed_mime_types TEXT[],
    file_size_limit    BIGINT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS storage.objects (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bucket_id   TEXT NOT NULL REFERENCES storage.buckets (id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    owner       UUID,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (bucket_id, name)
);

"#
}

/// Produces an UPSERT statement that registers (or updates) a single bucket.
fn bucket_upsert_sql(bucket: &StorageBucketAst) -> String {
    let public = if bucket.public { "true" } else { "false" };
    let mime = match &bucket.allowed_mime_types {
        Some(types) if !types.is_empty() => {
            let arr = types.iter().map(|t| format!("'{t}'")).collect::<Vec<_>>().join(", ");
            format!("ARRAY[{arr}]::TEXT[]")
        }
        _ => "NULL".to_string(),
    };
    let size_limit = bucket
        .file_size_limit
        .map(|s| s.to_string())
        .unwrap_or_else(|| "NULL".to_string());
    let id = &bucket.id;

    format!(
        "INSERT INTO storage.buckets (id, name, public, allowed_mime_types, file_size_limit)\n\
         VALUES ('{id}', '{id}', {public}, {mime}, {size_limit})\n\
         ON CONFLICT (id) DO UPDATE SET\n  \
           public             = EXCLUDED.public,\n  \
           allowed_mime_types = EXCLUDED.allowed_mime_types,\n  \
           file_size_limit    = EXCLUDED.file_size_limit,\n  \
           updated_at         = NOW();\n"
    )
}

/// Generates RLS policies for `storage.objects`, one set per (model, bucket) pair.
/// Policies gate access by `bucket_id` and inherit the model's access rule, falling
/// back to `auth.uid() IS NOT NULL` (authenticated) when no rule is defined.
fn generate_storage_rls(ast: &SchemaAst) -> String {
    let mut out = String::new();

    // Collect (model_table, bucket_id, access) for each image/file field.
    struct BucketAccess<'a> {
        table: &'a str,
        bucket_id: &'a str,
        read_expr: String,
        write_expr: String,
        delete_expr: String,
    }

    let mut entries: Vec<BucketAccess<'_>> = Vec::new();

    for model in &ast.models {
        for (_field_name, field) in &model.fields {
            let bucket_id = match field {
                FieldAst::Image(s) | FieldAst::File(s) => &s.bucket,
                _ => continue,
            };

            // Avoid duplicate entries for the same (table, bucket) pair.
            let already = entries
                .iter()
                .any(|e| e.table == model.table_name && e.bucket_id == bucket_id.as_str());
            if already {
                continue;
            }

            let read_expr = model
                .access
                .read
                .as_ref()
                .map(|r| format!("bucket_id = '{}' AND ({})", bucket_id, access_rule_to_expr(r)))
                .unwrap_or_else(|| {
                    format!(
                        "bucket_id = '{}' AND auth.uid() IS NOT NULL",
                        bucket_id
                    )
                });

            let write_expr = model
                .access
                .create
                .as_ref()
                .map(|r| format!("bucket_id = '{}' AND ({})", bucket_id, access_rule_to_expr(r)))
                .unwrap_or_else(|| {
                    format!(
                        "bucket_id = '{}' AND auth.uid() IS NOT NULL",
                        bucket_id
                    )
                });

            let delete_expr = model
                .access
                .delete
                .as_ref()
                .map(|r| format!("bucket_id = '{}' AND ({})", bucket_id, access_rule_to_expr(r)))
                .unwrap_or_else(|| {
                    format!(
                        "bucket_id = '{}' AND auth.uid() IS NOT NULL",
                        bucket_id
                    )
                });

            entries.push(BucketAccess {
                table: &model.table_name,
                bucket_id,
                read_expr,
                write_expr,
                delete_expr,
            });
        }
    }

    if entries.is_empty() {
        return out;
    }

    out.push_str("-- ─── Storage RLS ────────────────────────────────────────────────────────\n\n");
    out.push_str("ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;\n\n");

    for e in &entries {
        let table = e.table;
        let bucket_id = e.bucket_id;
        // Keep policy names short and collision-free: {table}_{bucket}_sel/ins/del
        let select_policy = format!("{table}_{bucket_id}_sel");
        let insert_policy = format!("{table}_{bucket_id}_ins");
        let delete_policy = format!("{table}_{bucket_id}_del");

        out.push_str(&format!(
            "-- Storage policies for model '{table}', bucket '{bucket_id}'\n\
             DROP POLICY IF EXISTS \"{select_policy}\" ON storage.objects;\n\
             CREATE POLICY \"{select_policy}\" ON storage.objects\n  \
               FOR SELECT USING (\n    {read_expr}\n  );\n\n\
             DROP POLICY IF EXISTS \"{insert_policy}\" ON storage.objects;\n\
             CREATE POLICY \"{insert_policy}\" ON storage.objects\n  \
               FOR INSERT WITH CHECK (\n    {write_expr}\n  );\n\n\
             DROP POLICY IF EXISTS \"{delete_policy}\" ON storage.objects;\n\
             CREATE POLICY \"{delete_policy}\" ON storage.objects\n  \
               FOR DELETE USING (\n    {delete_expr}\n  );\n\n",
            read_expr = e.read_expr,
            write_expr = e.write_expr,
            delete_expr = e.delete_expr,
        ));
    }

    out
}
