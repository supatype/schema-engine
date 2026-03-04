use anyhow::Result;
use super::ast::{FieldAst, JunctionTableAst, RelationCardinality, SchemaAst, StorageBucketAst};

/// Resolves relations, infers junction tables, and detects storage buckets.
pub fn resolve(mut ast: SchemaAst) -> Result<SchemaAst> {
    resolve_junction_tables(&mut ast);
    resolve_storage_buckets(&mut ast);
    Ok(ast)
}

fn resolve_junction_tables(ast: &mut SchemaAst) {
    for model in &ast.models {
        for (_field_name, field) in &model.fields {
            if let FieldAst::Relation(rel) = field {
                if matches!(rel.cardinality, RelationCardinality::ManyToMany) {
                    let junction_name = rel.through.clone().unwrap_or_else(|| {
                        let mut names = vec![model.table_name.clone(), rel.target.clone()];
                        names.sort();
                        names.join("_")
                    });

                    let already_exists = ast
                        .junction_tables
                        .iter()
                        .any(|j| j.name == junction_name);

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

fn resolve_storage_buckets(ast: &mut SchemaAst) {
    for model in &ast.models {
        for (_field_name, field) in &model.fields {
            if let FieldAst::Image(storage) | FieldAst::File(storage) = field {
                let already_exists = ast
                    .storage_buckets
                    .iter()
                    .any(|b| b.id == storage.bucket);
                if !already_exists {
                    ast.storage_buckets.push(StorageBucketAst {
                        id: storage.bucket.clone(),
                        public: false,
                        allowed_mime_types: None,
                        file_size_limit: None,
                    });
                }
            }
        }
    }
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
