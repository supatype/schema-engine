use super::ast::{
    FieldAst, JunctionTableAst, ModelAst, RelationCardinality, RelationFieldAst, SchemaAst,
    StorageBucketAst,
};
use crate::managed::clip_identifier;
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
                 The plugin may not work correctly. Update it or check compatibility.",
                plugin.name, plugin.plugin_api, SUPPORTED_PLUGIN_API
            ));
        }
    }
}

/// One junction per pair of models, whichever side declares the relation and in whatever order
/// (B6). `Post.tags: ManyToMany<Tag>` and `Tag.posts: ManyToMany<Post>` are one relation read
/// from both ends; each side naming its own table split it in two, so a tag added from a post was
/// not visible from the tag. A `through` name is the schema's and is kept as declared.
fn resolve_junction_tables(ast: &mut SchemaAst) {
    let mut found = Vec::new();
    for model in &ast.models {
        for rel in many_to_many(model) {
            let junction = match &rel.through {
                Some(name) => declared_junction(name, &model.name, &rel.target),
                None => derived_junction(ast, &model.name, &rel.target),
            };
            found.push(junction);
        }
    }
    for junction in found {
        if !ast.junction_tables.iter().any(|j| j.name == junction.name) {
            ast.junction_tables.push(junction);
        }
    }
}

/// `model`'s `manyToMany` relations.
fn many_to_many(model: &ModelAst) -> impl Iterator<Item = &RelationFieldAst> {
    model.fields.values().filter_map(|field| match field {
        FieldAst::Relation(rel) if matches!(rel.cardinality, RelationCardinality::ManyToMany) => {
            Some(rel)
        }
        _ => None,
    })
}

fn declared_junction(name: &str, model_a: &str, model_b: &str) -> JunctionTableAst {
    JunctionTableAst {
        name: name.to_string(),
        model_a: model_a.to_string(),
        model_b: model_b.to_string(),
        fk_a: format!("{}_id", to_snake_case(model_a)),
        fk_b: format!("{}_id", to_snake_case(model_b)),
    }
}

/// The junction between two models named by their tables, sorted: `post_tag` from either side.
fn derived_junction(ast: &SchemaAst, model: &str, target: &str) -> JunctionTableAst {
    let mut ends = [
        (effective_table(ast, model), model),
        (effective_table(ast, target), target),
    ];
    ends.sort();
    let name = format!("{}_{}", ends[0].0, ends[1].0);
    declared_junction(&name, ends[0].1, ends[1].1)
}

/// The table a model is stored in: its declared name, else the one the normaliser will give it.
fn effective_table(ast: &SchemaAst, model: &str) -> String {
    ast.models
        .iter()
        .find(|m| m.name == model)
        .map(|m| m.table_name())
        .filter(|table| !table.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| to_snake_case(model))
}

/// The names engines before B6 gave each derived junction, keyed by the junction's name now.
///
/// They joined the declaring model's table and the target's *model* name, sorted, so
/// `Post.tags: ManyToMany<Tag>` made `Tag_post` and `Tag.posts: ManyToMany<Post>` made `Post_tag`.
/// The differ renames one such table to the new name, and refuses when both exist, rather than
/// dropping the links a project already holds. Both names are as Postgres keeps them, which is how
/// the junction is named now and how the old table was stored.
pub fn legacy_junction_names(ast: &SchemaAst) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for model in &ast.models {
        for rel in many_to_many(model).filter(|rel| rel.through.is_none()) {
            let current = clip_identifier(&derived_junction(ast, &model.name, &rel.target).name);
            let mut old = [effective_table(ast, &model.name), rel.target.clone()];
            old.sort();
            let legacy = clip_identifier(&old.join("_"));
            if legacy != current && !out.contains(&(current.clone(), legacy.clone())) {
                out.push((current, legacy));
            }
        }
    }
    out
}

/// Merge declarative `storageBuckets` from the CLI input with buckets inferred from image/file fields.
/// Declarative rows win for `public`, mime allowlist, size limit, bucket RLS `access`, S3 policy JSON, and `access_mode`.
fn resolve_storage_buckets(ast: &mut SchemaAst) -> Result<()> {
    let mut by_id: HashMap<String, StorageBucketAst> = std::mem::take(&mut ast.storage_buckets)
        .into_iter()
        .map(|b| (b.id.clone(), b))
        .collect();
    add_field_only_buckets(&ast.models, &mut by_id);
    align_field_access_modes(&mut ast.models, &by_id);

    let mut list: Vec<StorageBucketAst> = by_id.into_values().collect();
    list.sort_by(|a, b| a.id.cmp(&b.id));
    ast.storage_buckets = list;
    Ok(())
}

/// A bucket for each one a model's image or file field names and no `Bucket<>` export declares.
/// A declared bucket takes precedence, and the first field to name a bucket gives it its mode.
fn add_field_only_buckets(models: &[ModelAst], by_id: &mut HashMap<String, StorageBucketAst>) {
    for field in models.iter().flat_map(|m| m.fields.values()) {
        if let FieldAst::Image(s) | FieldAst::File(s) = field {
            by_id
                .entry(s.bucket.clone())
                .or_insert_with(|| StorageBucketAst {
                    id: s.bucket.clone(),
                    // The field's mode, if it names one, is the bucket's; no mode is private.
                    public: None,
                    allowed_mime_types: None,
                    file_size_limit: None,
                    access_mode: s.access_mode,
                    access: None,
                    s3_bucket_policy: None,
                });
        }
    }
}

/// Each image and file field's `access_mode` set to its bucket's resolved one.
fn align_field_access_modes(models: &mut [ModelAst], by_id: &HashMap<String, StorageBucketAst>) {
    for field in models.iter_mut().flat_map(|m| m.fields.values_mut()) {
        if let FieldAst::Image(s) | FieldAst::File(s) = field {
            if let Some(b) = by_id.get(&s.bucket) {
                s.access_mode = Some(b.effective_access_mode());
            }
        }
    }
}

// Used by the storage generator, which the wasm build does not compile.
#[cfg(not(target_arch = "wasm32"))]
fn bucket_has_explicit_storage_access(access: &crate::parser::ast::AccessAst) -> bool {
    access.read.is_some()
        || access.create.is_some()
        || access.update.is_some()
        || access.delete.is_some()
}

// Used by the storage generator, which the wasm build does not compile.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn bucket_uses_declared_storage_rls(bucket: &StorageBucketAst) -> bool {
    bucket
        .access
        .as_ref()
        .is_some_and(bucket_has_explicit_storage_access)
}

// Used by the storage generator, which the wasm build does not compile.
#[cfg(not(target_arch = "wasm32"))]
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
