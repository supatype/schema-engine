use crate::parser::ast::{
    AccessAst, AccessRule, FieldAst, ModelAst, SchemaAst, StorageAccessMode, StorageBucketAst,
};
use crate::parser::resolver::{bucket_uses_declared_storage_rls, storage_policy_label};
use anyhow::Result;

/// Generates SQL for the storage subsystem:
///   1. `storage` schema + `storage.buckets` + `storage.objects` DDL (idempotent).
///   2. UPSERT for every bucket inferred from image/file fields.
///   3. Row-level security and the caller roles' privileges on `storage.objects`.
///
/// The policies on `storage.objects` are ledger objects ([`bucket_policies_sql`]): the reconcile
/// creates them, and drops the ones a schema that has removed its last bucket no longer asks for.
pub fn generate(ast: &SchemaAst) -> Result<String> {
    if ast.storage_buckets.is_empty() {
        return Ok("-- No storage buckets declared in schema.\n".to_string());
    }
    refuse_colliding_policy_labels(ast)?;

    let mut out = String::new();

    out.push_str(storage_schema_ddl());
    out.push('\n');

    out.push_str("-- Bucket registrations\n\n");
    for bucket in &ast.storage_buckets {
        out.push_str(&bucket_upsert_sql(bucket));
        out.push('\n');
    }

    out.push_str(&generate_storage_rls());

    Ok(out)
}

/// Refuse two bucket ids whose policies would share names.
///
/// A policy is named from the bucket id with every non-alphanumeric character made `_`, so
/// `user-avatars` and `user_avatars` both name `storage_user_avatars_*`, and whichever renders
/// second drops the first one's policies. The first bucket would then be refused everything while
/// its warnings said it was covered.
pub fn refuse_colliding_policy_labels(ast: &SchemaAst) -> Result<()> {
    let mut seen: std::collections::HashMap<String, &str> = std::collections::HashMap::new();
    for bucket in &ast.storage_buckets {
        let label = storage_policy_label(&bucket.id);
        if let Some(other) = seen.insert(label.clone(), &bucket.id) {
            anyhow::bail!(
                "Buckets \"{other}\" and \"{}\" would share storage policy names \
                 (storage_{label}_*), so one would remove the other's access rules. Rename one of them.",
                bucket.id
            );
        }
    }
    Ok(())
}

/// DDL that sets up the storage schema and tables.
/// Safe to run repeatedly: it uses IF NOT EXISTS throughout.
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
    version     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (bucket_id, name)
);

-- The key the live bytes are stored under is `name/<version>`, a fresh one per upload, so an
-- overwrite never replaces the bytes being served until its row commits. Null means the bytes are
-- at `name`, which is where every object written before versions lives.
ALTER TABLE storage.objects ADD COLUMN IF NOT EXISTS version TEXT;

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

/// The four operations on `storage.objects`, each governed by its own rule.
///
/// A rule that is left out produces no policy, and with RLS on, an operation no policy allows is
/// refused. That is the deny-by-default models already have. Buckets used to fill a missing rule
/// with "any signed-in user", which for `delete` meant anyone could remove anyone's files.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ObjectOp {
    Read,
    Create,
    Update,
    Delete,
}

/// What an operation is called: in the schema, in its policy's name, and in a warning.
struct OpNames {
    key: &'static str,
    /// `sel`, `ins` and `del` predate `update` and are kept so a push still replaces the policies
    /// earlier engines created.
    suffix: &'static str,
    refused: &'static str,
}

impl ObjectOp {
    const ALL: [ObjectOp; 4] = [Self::Read, Self::Create, Self::Update, Self::Delete];

    fn rule(self, access: &AccessAst) -> Option<&AccessRule> {
        match self {
            Self::Read => access.read.as_ref(),
            Self::Create => access.create.as_ref(),
            Self::Update => access.update.as_ref(),
            Self::Delete => access.delete.as_ref(),
        }
    }

    fn names(self) -> OpNames {
        let (key, suffix, refused) = match self {
            Self::Read => ("read", "sel", "reads through the API are refused"),
            Self::Create => ("create", "ins", "uploads are refused"),
            Self::Update => ("update", "upd", "overwrites are refused"),
            Self::Delete => ("delete", "del", "deletes are refused"),
        };
        OpNames {
            key,
            suffix,
            refused,
        }
    }

    fn clause(self, expr: &str) -> String {
        match self {
            Self::Read => format!("FOR SELECT USING (\n    {expr}\n  )"),
            Self::Create => format!("FOR INSERT WITH CHECK (\n    {expr}\n  )"),
            // An overwrite may only replace an object the rule allows, and only with one the rule
            // still allows, so the same rule is both the row selection and the result check.
            Self::Update => {
                format!("FOR UPDATE USING (\n    {expr}\n  ) WITH CHECK (\n    {expr}\n  )")
            }
            Self::Delete => format!("FOR DELETE USING (\n    {expr}\n  )"),
        }
    }
}

/// One named set of policies on `storage.objects`: a bucket's own, or a model's for a bucket one
/// of its file fields uses. `rules` is indexed like [`ObjectOp::ALL`]; a set with none declared
/// renders as drops only, which is what retires it.
struct ObjectPolicies<'a> {
    name: String,
    bucket_id: &'a str,
    comment: String,
    rules: [Option<&'a AccessRule>; 4],
}

impl<'a> ObjectPolicies<'a> {
    fn new(
        name: String,
        comment: String,
        bucket_id: &'a str,
        access: Option<&'a AccessAst>,
    ) -> Self {
        let rules = ObjectOp::ALL.map(|op| access.and_then(|a| op.rule(a)));
        Self {
            name,
            bucket_id,
            comment,
            rules,
        }
    }

    fn policy_name(&self, op: ObjectOp) -> String {
        format!("{}_{}", self.name, op.names().suffix)
    }

    /// The `CREATE POLICY` of every declared rule. A rule removed from the schema takes its policy
    /// with it because nothing desires that policy any more and the reconcile drops it.
    fn render(&self) -> String {
        let b = sql_quote_bucket_id(self.bucket_id);
        let mut out = format!("-- {}\n", self.comment);
        for (op, rule) in ObjectOp::ALL.into_iter().zip(&self.rules) {
            let Some(rule) = rule else { continue };
            let expr = format!(
                "bucket_id = '{b}' AND ({})",
                access_rule_to_storage_expr(rule)
            );
            out.push_str(&format!(
                "CREATE POLICY \"{}\" ON \"storage\".\"objects\"\n  {};\n",
                self.policy_name(op),
                op.clause(&expr),
            ));
        }
        out.push('\n');
        out
    }
}

/// Each `(model, bucket)` pair where a model's file or image field stores into the bucket.
fn model_bucket_uses(ast: &SchemaAst) -> Vec<(&ModelAst, &str)> {
    let mut seen = std::collections::HashSet::new();
    let mut uses = Vec::new();
    for model in &ast.models {
        for field in model.fields.values() {
            let bucket_id = match field {
                FieldAst::Image(s) | FieldAst::File(s) => s.bucket.as_str(),
                _ => continue,
            };
            if seen.insert((model.table_name(), bucket_id)) {
                uses.push((model, bucket_id));
            }
        }
    }
    uses
}

/// Every policy set on `storage.objects`, in emission order.
///
/// A bucket that declares its own `access` uses that and nothing else, so any set a model would
/// otherwise contribute for it is retired: left in place, it would be ORed with the bucket's rules
/// and grant what the bucket no longer does. A bucket that declares nothing still gets its own
/// set, retired, so the policies it had while it did declare rules are removed.
fn object_policy_sets(ast: &SchemaAst) -> Vec<ObjectPolicies<'_>> {
    let mut sets = Vec::new();
    let mut declared = std::collections::HashSet::new();
    for bucket in &ast.storage_buckets {
        let label = storage_policy_label(&bucket.id);
        let own = bucket
            .access
            .as_ref()
            .filter(|_| bucket_uses_declared_storage_rls(bucket));
        if own.is_some() {
            declared.insert(bucket.id.as_str());
        }
        sets.push(ObjectPolicies::new(
            format!("storage_{label}"),
            format!("Declarative storage policies for bucket id (sanitized label: {label})"),
            &bucket.id,
            own,
        ));
    }

    for (model, bucket_id) in model_bucket_uses(ast) {
        let table = model.table_name();
        let access = (!declared.contains(bucket_id)).then(|| model.access());
        sets.push(ObjectPolicies::new(
            format!("{table}_{bucket_id}"),
            format!("Storage policies for model '{table}', bucket '{bucket_id}'"),
            bucket_id,
            access,
        ));
    }
    sets
}

/// The policies on `storage.objects` the bucket rules and the models that store into buckets ask
/// for, one `CREATE POLICY` each: what the desired set reads them from (Phase 4.7b). Buckets with
/// declarative `access` get a single policy set per bucket; others inherit model `access`. The
/// reconcile creates them after the storage layer, which makes `storage.objects` and turns its
/// row-level security on, and drops one when nothing asks for it any more: a bucket removed, a
/// model renamed, a file field pointed elsewhere.
pub fn bucket_policies_sql(ast: &SchemaAst) -> String {
    object_policy_sets(ast)
        .iter()
        .map(ObjectPolicies::render)
        .collect()
}

/// Whether a policy has the shape engines before the managed marker gave a bucket's policies:
/// `storage_<label>_sel|ins|del` on `storage.objects`. Only the engine named policies so, so one
/// with no row is ours, and dropped when the schema no longer asks for it, as the sweep dropped
/// it: the caller roles hold INSERT, UPDATE and DELETE, so an old "any signed-in user" delete
/// policy would take effect. A model's policies from before the marker (`<table>_<bucket>_*`)
/// cannot be told from a hand-written one, so those are left alone.
pub fn is_unmarked_bucket_policy(schema: &str, table: &str, name: &str) -> bool {
    let label = name
        .strip_prefix("storage_")
        .and_then(|rest| {
            ["_sel", "_ins", "_del"]
                .iter()
                .find_map(|suffix| rest.strip_suffix(suffix))
        })
        .unwrap_or("");
    schema == "storage"
        && table == "objects"
        && !label.is_empty()
        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Row-level security and the caller roles' privileges on `storage.objects`. The policies that
/// decide are the reconcile's ([`bucket_policies_sql`]).
fn generate_storage_rls() -> String {
    let mut out = String::new();
    out.push_str("-- Storage RLS\n\n");
    out.push_str("ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;\n\n");

    // Immediately after the ENABLE, never before it, and never without it.
    //
    // The storage service runs every read, write and delete as the caller, so the reconcile's policies
    // decide. A role is refused before RLS is consulted unless it holds the grant for the command,
    // so each caller role needs all four. That is safe only because RLS is on: an operation no
    // policy allows is refused, so this exposes exactly what the schema declared. The ordering is
    // asserted by a test, because a grant that preceded the ENABLE would let any caller read,
    // replace or delete every object in the project.
    out.push_str("GRANT USAGE ON SCHEMA storage TO anon, authenticated;\n");
    out.push_str(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON storage.objects TO anon, authenticated;\n\n",
    );

    out
}

/// One warning per bucket operation that no rule allows, so a refusal is never a surprise.
///
/// Rules left out are refused, the same as for models. The read warning is skipped for a bucket
/// whose `accessMode` is `public`, because its public URL serves files without asking the policy.
pub fn rule_warnings(ast: &SchemaAst) -> Vec<String> {
    let sets = object_policy_sets(ast);
    let mut warnings = Vec::new();
    for bucket in &ast.storage_buckets {
        let public = matches!(bucket.access_mode, Some(StorageAccessMode::Public));
        for (i, op) in ObjectOp::ALL.into_iter().enumerate() {
            let allowed = sets
                .iter()
                .any(|s| s.bucket_id == bucket.id && s.rules[i].is_some());
            if allowed || (op == ObjectOp::Read && public) {
                continue;
            }
            let names = op.names();
            warnings.push(format!(
                "Bucket \"{}\" declares no {} rule: {}. Add `{}: BucketOwner` (or another rule) \
                 to its access to allow them.",
                bucket.id, names.key, names.refused, names.key,
            ));
        }
        warnings.extend(unreadable_change_warnings(&sets, &bucket.id));
    }
    warnings
}

/// An update or delete rule with no read rule beside it does nothing, and says nothing.
///
/// Postgres applies a table's SELECT policies to the rows an UPDATE or DELETE reads in its `WHERE`,
/// so with no read policy those commands match no rows. Warned even on a public bucket, whose public
/// URL serves files without asking the read policy: that is the case it is easiest to miss.
fn unreadable_change_warnings(sets: &[ObjectPolicies<'_>], bucket_id: &str) -> Vec<String> {
    let allows = |op: ObjectOp| {
        let i = ObjectOp::ALL.iter().position(|o| *o == op).unwrap_or(0);
        sets.iter()
            .any(|s| s.bucket_id == bucket_id && s.rules[i].is_some())
    };
    if allows(ObjectOp::Read) {
        return Vec::new();
    }
    [ObjectOp::Update, ObjectOp::Delete]
        .into_iter()
        .filter(|op| allows(*op))
        .map(|op| {
            format!(
                "Bucket \"{bucket_id}\" declares {} but no read rule: Postgres only lets a caller change \
                 objects it can read, so {} match nothing. Add a `read` rule.",
                op.names().key,
                if op == ObjectOp::Update { "overwrites" } else { "deletes" },
            )
        })
        .collect()
}
