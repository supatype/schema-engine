use super::accessors::db_table_name_mut;
use super::annotations::FieldAnnotations;
use super::ast::{DefaultValueAst, FieldAst, ScalarFieldAst, SchemaAst};
use super::resolver::to_snake_case;
#[allow(unused_imports)]
use indexmap::IndexMap;

/// Apply naming conventions and fill in defaults.
pub fn normalise(mut ast: SchemaAst) -> SchemaAst {
    for model in &mut ast.models {
        let model_name = model.name.clone();
        let table_name = db_table_name_mut(model);
        if table_name.is_empty() {
            *table_name = to_snake_case(&model_name);
        }

        let has_explicit_pk = model.fields.values().any(|f| match f {
            FieldAst::Text(s)
            | FieldAst::Uuid(s)
            | FieldAst::Integer(s)
            | FieldAst::BigInt(s)
            | FieldAst::Serial(s)
            | FieldAst::BigSerial(s) => s.primary_key,
            _ => false,
        });

        if !has_explicit_pk && !model.fields.contains_key("id") {
            model.fields.insert(
                "id".to_string(),
                FieldAst::Uuid(ScalarFieldAst {
                    pg_type: "UUID".to_string(),
                    required: true,
                    unique: false,
                    primary_key: true,
                    index: false,
                    default: Some(DefaultValueAst::GenRandomUuid),
                    check: None,
                    validation: None,
                    localized: false,
                    read_only: false,
                    sources: vec![],
                    template: None,
                    identity: None,
                    auto_increment: false,
                    generated: None,
                    annotations: FieldAnnotations {
                        db: super::annotations::DbFieldAnnotations {
                            pg_type: "UUID".to_string(),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                }),
            );
        }
        super::column_names::keep_as_postgres_does(model);
        default_owner_to_caller(model);
    }
    ast
}

/// What a caller's own id defaults to: the engine's claim reader, which `auth.uid()` aliases and
/// every owner rule compares against, so the default and the rule cannot disagree about who the
/// caller is.
pub const CALLER_ID_DEFAULT: &str = "_supatype.jwt_uid()";

/// An auth user id the create rule says must be the caller's defaults to the caller's id (C7).
///
/// `Owner<"user_id">` on `create` refuses any row whose `user_id` is not the caller's, so the one
/// value a client may send is one the database already knows. Without a default every insert had
/// to send it, and the generated `Insert` type required it. A forged id is still refused by the
/// rule; a declared default is left as it is.
fn default_owner_to_caller(model: &mut super::ast::ModelAst) {
    let owners: Vec<String> = model
        .access()
        .create
        .as_ref()
        .map(owners_in_rule)
        .unwrap_or_default();
    for owner in owners {
        if let Some(FieldAst::Uuid(field)) = model.fields.get_mut(&owner) {
            if field.annotations.db.auth_user_id && field.default.is_none() {
                field.default = Some(DefaultValueAst::Expression {
                    expr: CALLER_ID_DEFAULT.to_string(),
                });
            }
        }
    }
}

/// Every field an `Owner` names in `rule`, looking inside `any` and `all`.
fn owners_in_rule(rule: &super::ast::AccessRule) -> Vec<String> {
    use super::ast::AccessRule;
    match rule {
        AccessRule::Owner { field } => vec![field.clone()],
        AccessRule::Any { rules } | AccessRule::All { rules } => {
            rules.iter().flat_map(owners_in_rule).collect()
        }
        _ => Vec::new(),
    }
}
