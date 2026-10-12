//! Which fields an `Owner<"f">` rule may name.
//!
//! A row is owned through `id`, through a field of type UUID or SupatypeAuthUserId, or through a
//! relation that holds its key on this model (`RelatedTo`, `ManyToMany`). Anything else is refused
//! here, naming the field, its type and what is allowed: the policy it would compile to compares
//! `auth.uid()` with a value that cannot be a user id, so it would deny everyone without saying so.
//!
//! Every place a rule can stand is checked: the row clauses, the update check, the per-field rules
//! and the filter of a membership source. A filter reads another table, so its `Owner` is checked
//! against the model behind that table rather than the one the policy is attached to.
//!
//! A relation owner is also checked for what it reaches (D11). The model at the other end must be
//! a user's own, keyed by a `SupatypeAuthUserId`, or owned by an `Owner` rule of its own (O1); and
//! that owner must not be a relation to yet another model that is not a user's, since ownership is
//! followed through one relation only (O4). An owner that is a plain UUID, not marked as an auth
//! user id, is accepted with a warning: nothing says it holds one (O2).

use super::accessors::{
    db_table_name, field_annotations, is_user_identity_model, owner_field_on_model,
    resolve_owner_column,
};
use super::ast::{AccessRule, FieldAst, MembershipSource, ModelAst, SchemaAst};
use anyhow::{anyhow, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const ALLOWED: &str =
    "An owner must be \"id\", a relation field, or a field of type UUID or SupatypeAuthUserId";

/// Whether one field can own a row and, when it cannot, why not.
enum Eligibility {
    Owner,
    Refused(String),
}

/// One model's fields, classified once before any rule is rewritten.
struct Scope {
    model: String,
    fields: BTreeMap<String, Eligibility>,
    /// A relation's key column, and `<relation>_id`, each mapped to the relation, so
    /// `Owner<"author_id">` means the relation `author`.
    relation_keys: HashMap<String, String>,
    /// Each owning relation's target model.
    relation_targets: HashMap<String, String>,
    /// Keyed by a `SupatypeAuthUserId`: a user's own model.
    user_model: bool,
    /// The field this model is owned through, resolved as [`Scope::check`] resolves one.
    owner: Option<String>,
    /// The UUID fields, `id` included, not marked as an auth user id: an owner that is one of them
    /// is warned about (O2).
    plain_uuids: HashSet<String>,
}

impl Scope {
    fn read(model: &ModelAst) -> Self {
        let fields = model
            .fields
            .iter()
            .map(|(name, field)| (name.clone(), field_eligibility(name, field)))
            .collect();
        let relation_targets = model
            .fields
            .iter()
            .filter_map(|(name, field)| match field {
                FieldAst::Relation(rel) if rel.is_owning() => {
                    Some((name.clone(), rel.target.clone()))
                }
                _ => None,
            })
            .collect();
        let plain_uuids = model
            .fields
            .iter()
            .filter(|(_, f)| {
                matches!(f, FieldAst::Uuid(_)) && !field_annotations(f).db.auth_user_id
            })
            .map(|(name, _)| name.clone())
            .collect();
        let mut scope = Self {
            model: model.name.clone(),
            fields,
            relation_keys: relation_keys(model).collect(),
            relation_targets,
            user_model: is_user_identity_model(model),
            owner: None,
            plain_uuids,
        };
        scope.owner = owner_field_on_model(model)
            .map(|owner| scope.resolve(owner).unwrap_or_else(|| owner.to_string()));
        scope
    }

    /// `id` first, then every field that may own a row, in name order.
    fn eligible(&self) -> String {
        let named = self.fields.iter().filter_map(|(name, eligibility)| {
            (name != "id" && matches!(eligibility, Eligibility::Owner)).then_some(name.as_str())
        });
        std::iter::once("id")
            .chain(named)
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn refuse(&self, field: &str, reason: &str) -> anyhow::Error {
        anyhow!(
            "Model '{}': Owner<\"{field}\"> is invalid: {reason}. {ALLOWED}. \
             Eligible on this model: [{}]",
            self.model,
            self.eligible()
        )
    }

    /// A refusal of `Owner<"{field}">` for what it reaches rather than what it is.
    fn refuse_reach(&self, field: &str, reason: &str) -> anyhow::Error {
        anyhow!(
            "Model '{}': Owner<\"{field}\"> is invalid: {reason}",
            self.model
        )
    }

    /// Check one `Owner` field, rewriting a relation's key column (`author_id`) to the relation
    /// (`author`), the form the generators resolve.
    fn check(&self, field: &mut String) -> Result<()> {
        if field == "id" {
            return Ok(());
        }
        let Some(name) = self.resolve(field) else {
            return Err(self.refuse(field, &format!("there is no field '{field}'")));
        };
        match &self.fields[&name] {
            Eligibility::Owner => {
                *field = name;
                Ok(())
            }
            Eligibility::Refused(reason) => Err(self.refuse(field, reason)),
        }
    }

    /// The field an owner name refers to: itself, or the relation whose key column it is.
    fn resolve(&self, field: &str) -> Option<String> {
        if self.fields.contains_key(field) {
            return Some(field.to_string());
        }
        self.relation_keys.get(field).cloned()
    }
}

fn field_eligibility(name: &str, field: &FieldAst) -> Eligibility {
    match field {
        FieldAst::Uuid(_) => Eligibility::Owner,
        FieldAst::Relation(rel) if rel.is_owning() => Eligibility::Owner,
        FieldAst::Relation(_) => Eligibility::Refused(format!(
            "field '{name}' is a relation that keeps its key on the other model"
        )),
        other => Eligibility::Refused(format!(
            "field '{name}' is of type {}",
            field_kind_name(other)
        )),
    }
}

/// Each owning relation's key column and its `<relation>_id` spelling, paired with the relation.
fn relation_keys(model: &ModelAst) -> impl Iterator<Item = (String, String)> + '_ {
    model
        .fields
        .iter()
        .filter(|(_, field)| matches!(field, FieldAst::Relation(rel) if rel.is_owning()))
        .flat_map(move |(name, _)| {
            [resolve_owner_column(model, name), format!("{name}_id")].map(|key| (key, name.clone()))
        })
}

/// The AST's own name for a field's kind (`text`, `integer`, ...), as the schema JSON spells it.
fn field_kind_name(field: &FieldAst) -> String {
    serde_json::to_value(field)
        .ok()
        .and_then(|value| value.get("kind")?.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

/// What every model's fields can own, and which model each table belongs to.
struct Scopes {
    by_model: HashMap<String, Scope>,
    model_by_table: HashMap<String, String>,
}

impl Scopes {
    fn read(ast: &SchemaAst) -> Self {
        Self {
            by_model: ast
                .models
                .iter()
                .map(|m| (m.name.clone(), Scope::read(m)))
                .collect(),
            model_by_table: ast
                .models
                .iter()
                .map(|m| (db_table_name(m).to_string(), m.name.clone()))
                .collect(),
        }
    }

    /// The scope a membership filter reads, or `None` for a table no model declares: its columns
    /// are not known here, and Postgres checks them when the policy is created.
    fn for_table(&self, table: &str) -> Option<&Scope> {
        self.by_model.get(self.model_by_table.get(table)?)
    }

    /// Refuse `Owner<"{written}">` on `scope`, resolved to `field`, when it is a relation that reaches
    /// a model no caller's id can match through (O1), or one owned through a second relation (O4).
    fn check_reach(&self, scope: &Scope, field: &str, written: &str) -> Result<()> {
        let Some(target) = self.target_of(scope, field) else {
            return Ok(());
        };
        if target.user_model {
            return Ok(());
        }
        let Some(owner) = target.owner.as_deref() else {
            return Err(scope.refuse_reach(written, &unowned(target, scope)));
        };
        match self.target_of(target, owner) {
            Some(next) if !next.user_model => {
                Err(scope.refuse_reach(written, &chained(target, owner, next, scope)))
            }
            _ => Ok(()),
        }
    }

    /// The model `field` of `scope` reaches, when it is an owning relation to a model declared here.
    fn target_of(&self, scope: &Scope, field: &str) -> Option<&Scope> {
        self.by_model.get(scope.relation_targets.get(field)?)
    }
}

/// Why an owner relation to `target` is refused when nothing owns it (O1).
fn unowned(target: &Scope, scope: &Scope) -> String {
    format!(
        "it reaches model '{target}', which is neither a user model (keyed by a \
         SupatypeAuthUserId) nor owned by an Owner rule of its own, so no caller's id could ever \
         match it. Key '{target}' by SupatypeAuthUserId, give it an Owner rule, or own '{model}' \
         through a field that holds the user's id",
        target = target.model,
        model = scope.model
    )
}

/// Why an owner relation to `target` is refused when `target` is owned through a second relation,
/// `owner`, to `next` (O4).
fn chained(target: &Scope, owner: &str, next: &Scope, scope: &Scope) -> String {
    format!(
        "it reaches model '{target}', which is owned through its relation '{owner}' to model \
         '{next}': a chain of more than one relation, and ownership is followed through one. Own \
         '{model}' through a field that holds the user's id, or own '{target}' through one",
        target = target.model,
        next = next.model,
        model = scope.model
    )
}

/// Check every `Owner` in the schema, normalising relation key columns to their relation.
pub fn validate(ast: &mut SchemaAst) -> Result<()> {
    let scopes = Scopes::read(ast);
    let mut warnings = BTreeSet::new();
    for model in &mut ast.models {
        let scope = &scopes.by_model[&model.name];
        let access = &mut model.annotations.platform.access;
        let clauses = [
            &mut access.read,
            &mut access.create,
            &mut access.update,
            &mut access.update_check,
            &mut access.delete,
        ];
        let field_rules = access
            .fields
            .values_mut()
            .flat_map(|rules| [&mut rules.read, &mut rules.write]);
        for rule in clauses.into_iter().chain(field_rules).flatten() {
            check_rule(rule, scope, &scopes, &mut warnings)?;
        }
    }
    ast.warnings.extend(warnings);
    Ok(())
}

fn check_rule(
    rule: &mut AccessRule,
    scope: &Scope,
    scopes: &Scopes,
    warnings: &mut BTreeSet<String>,
) -> Result<()> {
    match rule {
        AccessRule::Owner { field } => {
            let written = field.clone();
            scope.check(field)?;
            scopes.check_reach(scope, field, &written)?;
            if scope.plain_uuids.contains(field.as_str()) {
                warnings.insert(plain_uuid_owner(scope, field));
            }
            Ok(())
        }
        AccessRule::Any { rules } | AccessRule::All { rules } => rules
            .iter_mut()
            .try_for_each(|inner| check_rule(inner, scope, scopes, warnings)),
        AccessRule::Not { rule } => check_rule(rule, scope, scopes, warnings),
        AccessRule::In { source, .. } | AccessRule::Exists { source } => {
            check_filter(source, scopes, warnings)
        }
        _ => Ok(()),
    }
}

/// The warning for an owner that is a plain UUID, not marked as an auth user id (O2): the policy
/// compares the caller's id with it, and nothing says it holds one.
fn plain_uuid_owner(scope: &Scope, field: &str) -> String {
    format!(
        "Model '{}': Owner<\"{field}\"> compares the caller's id with a plain UUID. Declare \
         '{field}' as SupatypeAuthUserId if it holds an auth user's id: nothing checks that it does.",
        scope.model
    )
}

fn check_filter(
    source: &mut MembershipSource,
    scopes: &Scopes,
    warnings: &mut BTreeSet<String>,
) -> Result<()> {
    let MembershipSource::Rows {
        table,
        filter: Some(filter),
        ..
    } = source
    else {
        return Ok(());
    };
    match scopes.for_table(table) {
        Some(scope) => check_rule(filter, scope, scopes, warnings),
        None => Ok(()),
    }
}
