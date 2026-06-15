use super::ast::{
    AccessAst, FieldAst, JunctionTableAst, RelationCardinality, SchemaAst, StorageAccessMode,
    StorageBucketAst,
};
use anyhow::{bail, Result};
use std::collections::HashMap;

/// The plugin API version this engine build supports.
pub const SUPPORTED_PLUGIN_API: u32 = 1;

/// Resolves relations, infers junction tables, detects storage buckets,
/// and checks plugin API compatibility.
pub fn resolve(mut ast: SchemaAst) -> Result<SchemaAst> {
    resolve_junction_tables(&mut ast);
    resolve_storage_buckets(&mut ast)?;
    check_plugin_versions(&mut ast);
    validate_slug_source_fields(&ast)?;
    validate_computed_from_source_fields(&ast)?;
    Ok(ast)
}

/// Slug fields reference a `from` column; ensure it exists on the same model.
fn validate_slug_source_fields(ast: &SchemaAst) -> Result<()> {
    for model in &ast.models {
        for (field_name, field) in &model.fields {
            if let FieldAst::Slug(slug) = field {
                if !model.fields.contains_key(&slug.from) {
                    bail!(
                        "Model '{}': slug field '{}' references unknown source field '{}'",
                        model.name,
                        field_name,
                        slug.from
                    );
                }
            }
        }
    }
    Ok(())
}

/// `FieldAst::Text` with `sources` or `template` (`ComputedFrom`) must reference fields on the same model.
fn validate_computed_from_source_fields(ast: &SchemaAst) -> Result<()> {
    for model in &ast.models {
        for (field_name, field) in &model.fields {
            if let FieldAst::Text(t) = field {
                let has_preview =
                    !t.sources.is_empty() || t.template.as_ref().is_some_and(|s| !s.is_empty());
                if !has_preview {
                    continue;
                }
                for src in &t.sources {
                    if !model.fields.contains_key(src) {
                        bail!(
                            "Model '{}': field '{}' (ComputedFrom) references unknown source field '{}'",
                            model.name, field_name, src
                        );
                    }
                    if src == field_name {
                        bail!(
                            "Model '{}': field '{}' lists itself in `sources`",
                            model.name,
                            field_name
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// Emits a warning for every registered plugin whose declared pluginApi version
/// differs from SUPPORTED_PLUGIN_API.
fn check_plugin_versions(ast: &mut SchemaAst) {
    for plugin in &ast.plugins {
        if plugin.plugin_api != SUPPORTED_PLUGIN_API {
            ast.warnings.push(format!(
                "Plugin '{}' declares pluginApi {} but this engine supports pluginApi {}. \
                 The plugin may not work correctly — update it or check compatibility.",
                plugin.name, plugin.plugin_api, SUPPORTED_PLUGIN_API
            ));
        }
    }
}

fn resolve_junction_tables(ast: &mut SchemaAst) {
    for model in &ast.models {
        for field in model.fields.values() {
            if let FieldAst::Relation(rel) = field {
                if matches!(rel.cardinality, RelationCardinality::ManyToMany) {
                    let junction_name = rel.through.clone().unwrap_or_else(|| {
                        let mut names = [model.table_name().to_string(), rel.target.clone()];
                        names.sort();
                        names.join("_")
                    });

                    let already_exists =
                        ast.junction_tables.iter().any(|j| j.name == junction_name);

                    if !already_exists {
                        ast.junction_tables.push(JunctionTableAst {
                            name: junction_name,
                            model_a: model.name.clone(),
                            model_b: rel.target.clone(),
                            fk_a: format!("{}_id", to_snake_case(&model.name)),
                            fk_b: format!("{}_id", to_snake_case(&rel.target)),
                        });
                    }
                }
            }
        }
    }
}

/// Merge declarative `storageBuckets` from the CLI input with buckets inferred from image/file fields.
/// Declarative rows win for `public`, mime allowlist, size limit, bucket RLS `access`, S3 policy JSON, and `access_mode`.
fn resolve_storage_buckets(ast: &mut SchemaAst) -> Result<()> {
    let mut by_id: HashMap<String, StorageBucketAst> = HashMap::new();

    for b in std::mem::take(&mut ast.storage_buckets) {
        let mut b = b;
        normalize_storage_bucket_row(&mut b);
        by_id.insert(b.id.clone(), b);
    }

    // ── Buckets referenced only by models (no `Bucket<>` export) ───────────────
    let mut referenced: Vec<(String, Option<StorageAccessMode>)> = Vec::new();
    for model in &ast.models {
        for field in model.fields.values() {
            if let FieldAst::Image(s) | FieldAst::File(s) = field {
                referenced.push((s.bucket.clone(), s.access_mode));
            }
        }
    }

    for (bucket_id, field_access_mode) in referenced {
        use std::collections::hash_map::Entry;
        match by_id.entry(bucket_id.clone()) {
            Entry::Occupied(_) => {
                // Declarative config takes precedence — do not patch from fields.
            }
            Entry::Vacant(v) => {
                let public = matches!(field_access_mode.as_ref(), Some(StorageAccessMode::Public));
                let access_mode = Some(match field_access_mode {
                    Some(m) => m,
                    None => {
                        if public {
                            StorageAccessMode::Public
                        } else {
                            StorageAccessMode::Private
                        }
                    }
                });
                v.insert(StorageBucketAst {
                    id: bucket_id,
                    public,
                    allowed_mime_types: None,
                    file_size_limit: None,
                    access_mode,
                    access: None,
                    s3_bucket_policy: None,
                });
            }
        }
    }

    for b in by_id.values_mut() {
        normalize_storage_bucket_row(b);
    }

    // Keep field-level `access_mode` aligned with the resolved bucket visibility.
    for model in &mut ast.models {
        for field in model.fields.values_mut() {
            if let FieldAst::Image(s) | FieldAst::File(s) = field {
                if let Some(b) = by_id.get(&s.bucket) {
                    s.access_mode = Some(bucket_to_field_access_mode(b));
                }
            }
        }
    }

    let mut list: Vec<StorageBucketAst> = by_id.into_values().collect();
    list.sort_by(|a, b| a.id.cmp(&b.id));
    ast.storage_buckets = list;
    Ok(())
}

fn normalize_storage_bucket_row(bucket: &mut StorageBucketAst) {
    match bucket.access_mode {
        Some(StorageAccessMode::Public) => bucket.public = true,
        Some(StorageAccessMode::Private) | Some(StorageAccessMode::Custom) => bucket.public = false,
        None => {
            bucket.access_mode = Some(if bucket.public {
                StorageAccessMode::Public
            } else {
                StorageAccessMode::Private
            });
        }
    }
}

fn bucket_to_field_access_mode(bucket: &StorageBucketAst) -> StorageAccessMode {
    bucket.access_mode.unwrap_or(if bucket.public {
        StorageAccessMode::Public
    } else {
        StorageAccessMode::Private
    })
}

fn bucket_has_explicit_storage_access(access: &AccessAst) -> bool {
    access.read.is_some() || access.create.is_some() || access.delete.is_some()
}

pub(crate) fn bucket_uses_declared_storage_rls(bucket: &StorageBucketAst) -> bool {
    bucket
        .access
        .as_ref()
        .is_some_and(bucket_has_explicit_storage_access)
}

pub(crate) fn storage_policy_label(bucket_id: &str) -> String {
    bucket_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

pub fn to_snake_case(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_lowercase().next().unwrap());
    }
    out
}

/// Resolve a `supatype:*` system model reference token to its (schema, table) pair.
///
/// Returns `None` for unknown tokens (treated as user model names by the caller).
pub fn resolve_system_ref(token: &str) -> Option<(&'static str, &'static str)> {
    match token {
        "supatype:user" => Some(("auth", "users")),
        _ => None,
    }
}
