use crate::parser::ast::{AccessRule, FieldAst, SchemaAst, StorageAccessMode, StorageBucketAst};
use crate::parser::resolver::{bucket_uses_declared_storage_rls, storage_policy_label};
use anyhow::Result;

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

    out.push_str("-- Bucket registrations\n\n");
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
    r#"-- Storage schema
-- Safe to run repeatedly (IF NOT EXISTS / CREATE OR REPLACE).

CREATE SCHEMA IF NOT EXISTS storage;

CREATE TABLE IF NOT EXISTS storage.buckets (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    public             BOOLEAN NOT NULL DEFAULT false,
    allowed_mime_types TEXT[],
    file_size_limit    BIGINT,
    access_mode        TEXT,
    s3_bucket_policy   TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE storage.buckets ADD COLUMN IF NOT EXISTS access_mode TEXT;
ALTER TABLE storage.buckets ADD COLUMN IF NOT EXISTS s3_bucket_policy TEXT;

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
            let arr = types
                .iter()
                .map(|t| format!("'{}'", t.replace('\'', "''")))
                .collect::<Vec<_>>()
                .join(", ");
            format!("ARRAY[{arr}]::TEXT[]")
        }
        _ => "NULL".to_string(),
    };
    let size_limit = bucket
        .file_size_limit
        .map(|s| s.to_string())
        .unwrap_or_else(|| "NULL".to_string());
    let id = bucket.id.replace('\'', "''");
    let access_mode_sql = match &bucket.access_mode {
        Some(StorageAccessMode::Public) => "'public'".to_string(),
        Some(StorageAccessMode::Private) => "'private'".to_string(),
        Some(StorageAccessMode::Custom) => "'custom'".to_string(),
        None => "NULL".to_string(),
    };
    let policy_esc = bucket
        .s3_bucket_policy
        .as_ref()
        .map(|p| format!("'{}'", p.replace('\'', "''")))
        .unwrap_or_else(|| "NULL".to_string());

    format!(
        "INSERT INTO storage.buckets (id, name, public, allowed_mime_types, file_size_limit, access_mode, s3_bucket_policy)\n\
         VALUES ('{id}', '{id}', {public}, {mime}, {size_limit}, {access_mode}, {policy_esc})\n\
         ON CONFLICT (id) DO UPDATE SET\n  \
           public             = EXCLUDED.public,\n  \
           allowed_mime_types = EXCLUDED.allowed_mime_types,\n  \
           file_size_limit    = EXCLUDED.file_size_limit,\n  \
           access_mode        = EXCLUDED.access_mode,\n  \
           s3_bucket_policy   = EXCLUDED.s3_bucket_policy,\n  \
           updated_at         = NOW();\n",
        access_mode = access_mode_sql,
        policy_esc = policy_esc,
    )
}

fn sql_quote_bucket_id(bucket_id: &str) -> String {
    bucket_id.replace('\'', "''")
}

/// Storage policies run on storage.objects, so owner checks must reference the
/// objects.owner column rather than model-specific FK columns.
fn access_rule_to_storage_expr(rule: &AccessRule) -> String {
    match rule {
        // Constraint-only, refused inside `access` by the CLI. Denies rather than grants.
        AccessRule::Matches { .. } => "false".to_string(),
        AccessRule::Owner { .. } => "auth.uid() = owner".to_string(),
        AccessRule::Any { rules } => rules
            .iter()
            .map(|r| {
                let expr = access_rule_to_storage_expr(r);
                if matches!(r, AccessRule::Any { .. }) {
                    format!("({expr})")
                } else {
                    expr
                }
            })
            .collect::<Vec<_>>()
            .join("\n    OR\n    "),
        AccessRule::Public => "TRUE".to_string(),
        AccessRule::Private => "FALSE".to_string(),
        AccessRule::Authenticated => "auth.uid() IS NOT NULL".to_string(),
        AccessRule::Role { roles } => {
            if roles.len() == 1 {
                format!("auth.role() = '{}'", roles[0])
            } else {
                let arr = roles
                    .iter()
                    .map(|r| format!("'{r}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("auth.role() = ANY(ARRAY[{arr}])")
            }
        }
        // Storage policies run on `storage.objects`, which has none of the
        // model's columns. A rule naming one cannot be evaluated here, so it
        // denies rather than being rendered against a table where the column
        // means something else or nothing at all. `Bucket*` rules are the
        // supported vocabulary for buckets.
        AccessRule::All { .. }
        | AccessRule::Not { .. }
        | AccessRule::Compare { .. }
        | AccessRule::NullCheck { .. }
        | AccessRule::In { .. }
        | AccessRule::Exists { .. } => "FALSE".to_string(),
    }
}

fn access_exprs_for_bucket(
    bucket_id: &str,
    access: &crate::parser::ast::AccessAst,
) -> (String, String, String) {
    let b = sql_quote_bucket_id(bucket_id);
    let read_expr = access
        .read
        .as_ref()
        .map(|r| format!("bucket_id = '{b}' AND ({})", access_rule_to_storage_expr(r)))
        .unwrap_or_else(|| format!("bucket_id = '{b}' AND auth.uid() IS NOT NULL"));
    let write_expr = access
        .create
        .as_ref()
        .map(|r| format!("bucket_id = '{b}' AND ({})", access_rule_to_storage_expr(r)))
        .unwrap_or_else(|| format!("bucket_id = '{b}' AND auth.uid() IS NOT NULL"));
    let delete_expr = access
        .delete
        .as_ref()
        .map(|r| format!("bucket_id = '{b}' AND ({})", access_rule_to_storage_expr(r)))
        .unwrap_or_else(|| format!("bucket_id = '{b}' AND auth.uid() IS NOT NULL"));
    (read_expr, write_expr, delete_expr)
}

/// Generates RLS policies for `storage.objects`.
/// Buckets with declarative `access` get a single policy set per bucket; others inherit model `access`.
fn generate_storage_rls(ast: &SchemaAst) -> String {
    let mut out = String::new();

    let mut bucket_level = Vec::new();
    for bucket in &ast.storage_buckets {
        if !bucket_uses_declared_storage_rls(bucket) {
            continue;
        }
        let Some(access) = bucket.access.as_ref() else {
            continue;
        };
        let label = storage_policy_label(&bucket.id);
        let bq = sql_quote_bucket_id(&bucket.id);
        let (read_expr, write_expr, delete_expr) = access_exprs_for_bucket(&bucket.id, access);
        bucket_level.push((label, bq, read_expr, write_expr, delete_expr));
    }

    struct ModelBucketAccess<'a> {
        table: &'a str,
        bucket_id: &'a str,
        read_expr: String,
        write_expr: String,
        delete_expr: String,
    }

    let declared: std::collections::HashSet<String> = ast
        .storage_buckets
        .iter()
        .filter(|b| bucket_uses_declared_storage_rls(b))
        .map(|b| b.id.clone())
        .collect();

    let mut model_entries: Vec<ModelBucketAccess<'_>> = Vec::new();

    for model in &ast.models {
        for field in model.fields.values() {
            let bucket_id = match field {
                FieldAst::Image(s) | FieldAst::File(s) => &s.bucket,
                _ => continue,
            };

            if declared.contains(bucket_id.as_str()) {
                continue;
            }

            let already = model_entries
                .iter()
                .any(|e| e.table == model.table_name() && e.bucket_id == bucket_id.as_str());
            if already {
                continue;
            }

            let bq = sql_quote_bucket_id(bucket_id);
            let read_expr = model
                .access()
                .read
                .as_ref()
                .map(|r| {
                    format!(
                        "bucket_id = '{bq}' AND ({})",
                        access_rule_to_storage_expr(r)
                    )
                })
                .unwrap_or_else(|| format!("bucket_id = '{bq}' AND auth.uid() IS NOT NULL"));

            let write_expr = model
                .access()
                .create
                .as_ref()
                .map(|r| {
                    format!(
                        "bucket_id = '{bq}' AND ({})",
                        access_rule_to_storage_expr(r)
                    )
                })
                .unwrap_or_else(|| format!("bucket_id = '{bq}' AND auth.uid() IS NOT NULL"));

            let delete_expr = model
                .access()
                .delete
                .as_ref()
                .map(|r| {
                    format!(
                        "bucket_id = '{bq}' AND ({})",
                        access_rule_to_storage_expr(r)
                    )
                })
                .unwrap_or_else(|| format!("bucket_id = '{bq}' AND auth.uid() IS NOT NULL"));

            model_entries.push(ModelBucketAccess {
                table: model.table_name(),
                bucket_id,
                read_expr,
                write_expr,
                delete_expr,
            });
        }
    }

    if bucket_level.is_empty() && model_entries.is_empty() {
        return out;
    }

    out.push_str("-- Storage RLS\n\n");
    out.push_str("ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;\n\n");

    // Immediately after the ENABLE, never before it, and never without it.
    //
    // The policies below are the bucket's declared read rule, and until now nothing evaluated
    // them: the storage service connects as a superuser, which bypasses row level security, and
    // decided access itself from `access_mode` alone. That hardcoded owner-only for every private
    // bucket, so a bucket declaring `read: BucketLoggedIn` refused every caller but the uploader
    // while the correct policy sat unreached.
    //
    // The service now switches to the caller's role and asks Postgres. That is refused before RLS
    // is consulted unless the role can select the table at all, and no role held a grant here.
    //
    // Safe only because RLS is on: a bucket with no policy default-denies, so this exposes exactly
    // what the schema said to expose and nothing else. The ordering is asserted by a test, because
    // a grant that preceded the ENABLE would publish every object in the project.
    out.push_str("GRANT SELECT ON storage.objects TO anon, authenticated;\n\n");

    for (label, _bq, read_expr, write_expr, delete_expr) in &bucket_level {
        let select_policy = format!("storage_{label}_sel");
        let insert_policy = format!("storage_{label}_ins");
        let delete_policy = format!("storage_{label}_del");
        out.push_str(&format!(
            "-- Declarative storage policies for bucket id (sanitized label: {label})\n\
             DROP POLICY IF EXISTS \"{select_policy}\" ON storage.objects;\n\
             CREATE POLICY \"{select_policy}\" ON storage.objects\n  \
               FOR SELECT USING (\n    {read_expr}\n  );\n\n\
             DROP POLICY IF EXISTS \"{insert_policy}\" ON storage.objects;\n\
             CREATE POLICY \"{insert_policy}\" ON storage.objects\n  \
               FOR INSERT WITH CHECK (\n    {write_expr}\n  );\n\n\
             DROP POLICY IF EXISTS \"{delete_policy}\" ON storage.objects;\n\
             CREATE POLICY \"{delete_policy}\" ON storage.objects\n  \
               FOR DELETE USING (\n    {delete_expr}\n  );\n\n",
            read_expr = read_expr,
            write_expr = write_expr,
            delete_expr = delete_expr,
        ));
    }

    for e in &model_entries {
        let table = e.table;
        let bucket_id = e.bucket_id;
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
