//! The names GraphQL gives each end of a relation: the ones the schema declared.
//!
//! pg_graphql names a relation after the tables it joins. A key from `talk` to `speaker` is
//! `speaker` on the talk and `talkCollection` on the speaker, whatever the schema called either
//! end, so `talks: HasMany<Talk>` promised a field GraphQL did not have. pg_graphql reads other
//! names from an `@graphql` directive in the key's comment: `foreign_name` for the field on the
//! table holding the key, `local_name` for the field on the table it points at.
//!
//! The directive is re-asserted on every push, after the keys exist, and written only where the
//! comment does not already say it, so a settled push changes nothing. What else the comment holds
//! is kept: the directive replaces only an earlier directive line, and goes last, because
//! pg_graphql reads it with a greedy match up to the last `)`.
//!
//! An end the schema does not name keeps pg_graphql's own name. A reverse is named only when the
//! far model declares exactly one `hasMany` or `hasOne` back that this key can be: with two keys to
//! the same model and an inverse that names neither column, a guess could put the name on the wrong
//! key. A name that is already a column of its table is left out too, since the field would clash.

use crate::parser::accessors::{
    column_names_for, db_foreign_key, db_table_name, default_foreign_key_column,
};
use crate::parser::ast::{FieldAst, ModelAst, RelationCardinality, RelationFieldAst, SchemaAst};
use crate::sql_quote::{quote_literal, quote_qualified};

/// Both names of one single-column key, as the schema declared them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationNames {
    /// The table holding the key.
    pub table: String,
    /// The key's column.
    pub column: String,
    /// The table the key points at.
    pub foreign_table: String,
    /// The column the key points at.
    pub foreign_column: String,
    /// The field on `table` that reads the row the key points at.
    pub forward: Option<String>,
    /// The field on the referenced table that reads the rows holding the key.
    pub reverse: Option<String>,
    /// Whether `reverse` is a `hasOne`: one row under tier 1, where the key is unique.
    pub reverse_is_one: bool,
}

impl RelationNames {
    /// The `belongsTo` field `field_name` of `model`, when it points at another model.
    pub fn of(
        ast: &SchemaAst,
        model: &ModelAst,
        field_name: &str,
        field: &FieldAst,
    ) -> Option<RelationNames> {
        let FieldAst::Relation(rel) = field else {
            return None;
        };
        if !matches!(rel.cardinality, RelationCardinality::BelongsTo) {
            return None;
        }
        let target = ast.models.iter().find(|m| m.name == rel.target)?;
        let column = db_foreign_key(field, field_name)
            .unwrap_or_else(|| default_foreign_key_column(field_name));
        let reverse = inverse_of(model, &column, target).filter(|(n, _)| !is_column(target, n));
        Some(RelationNames {
            table: db_table_name(model).to_string(),
            forward: Some(field_name.to_string()).filter(|n| !is_column(model, n)),
            column,
            foreign_table: db_table_name(target).to_string(),
            foreign_column: rel.references.clone().unwrap_or_else(|| "id".into()),
            reverse_is_one: reverse.as_ref().is_some_and(|(_, one)| *one),
            reverse: reverse.map(|(name, _)| name),
        })
    }

    /// The directive's keys for the names there are, `None` when there is neither.
    pub fn directive(&self) -> Option<serde_json::Value> {
        names_spec(self.forward.as_ref(), self.reverse.as_ref())
    }

    /// [`RelationNames::directive`] for a key between `api` views, which leaves a `hasOne`'s
    /// reverse to pg_graphql: a view has no unique index, so the reverse is a collection there
    /// whatever it is called, and calling it by the one-row name would only make the error less
    /// clear.
    pub fn view_directive(&self) -> Option<serde_json::Value> {
        let reverse = self.reverse.as_ref().filter(|_| !self.reverse_is_one);
        names_spec(self.forward.as_ref(), reverse)
    }
}

/// `foreign_name` and `local_name` for the names given, `None` when neither is.
fn names_spec(forward: Option<&String>, reverse: Option<&String>) -> Option<serde_json::Value> {
    let mut spec = serde_json::Map::new();
    if let Some(forward) = forward {
        spec.insert("foreign_name".into(), forward.clone().into());
    }
    if let Some(reverse) = reverse {
        spec.insert("local_name".into(), reverse.clone().into());
    }
    (!spec.is_empty()).then_some(serde_json::Value::Object(spec))
}

/// Every model's keys to another model, with their names.
pub fn relation_names(ast: &SchemaAst) -> Vec<RelationNames> {
    ast.models
        .iter()
        .flat_map(|model| model_relation_names(ast, model))
        .collect()
}

/// `model`'s keys to another model, a self-reference included, with their names.
pub fn model_relation_names(ast: &SchemaAst, model: &ModelAst) -> Vec<RelationNames> {
    model
        .fields
        .iter()
        .filter_map(|(name, field)| RelationNames::of(ast, model, name, field))
        .collect()
}

/// The one field on `target` that reads `owner`'s rows through the key on `column`, and whether
/// it is a `hasOne`.
fn inverse_of(owner: &ModelAst, column: &str, target: &ModelAst) -> Option<(String, bool)> {
    let inverses: Vec<(&String, &RelationFieldAst)> = target
        .fields
        .iter()
        .filter_map(|(name, field)| match field {
            FieldAst::Relation(rel) if is_inverse(rel, owner) => Some((name, rel)),
            _ => None,
        })
        .collect();
    let keyed_by = |key: Option<&str>| -> Vec<(String, bool)> {
        inverses
            .iter()
            .filter(|(_, rel)| rel.foreign_key.as_deref() == key)
            .map(|(name, rel)| {
                let one = matches!(rel.cardinality, RelationCardinality::HasOne);
                ((*name).clone(), one)
            })
            .collect()
    };
    if let [only] = &keyed_by(Some(column))[..] {
        return Some(only.clone());
    }
    match &keyed_by(None)[..] {
        [only] if keys_to(owner, &target.name) == 1 => Some(only.clone()),
        _ => None,
    }
}

/// Whether `rel` is a `hasMany` or `hasOne` reading `owner`'s rows.
fn is_inverse(rel: &RelationFieldAst, owner: &ModelAst) -> bool {
    rel.target == owner.name
        && matches!(
            rel.cardinality,
            RelationCardinality::HasMany | RelationCardinality::HasOne
        )
}

/// How many `belongsTo` relations `model` has to `target`.
fn keys_to(model: &ModelAst, target: &str) -> usize {
    model
        .fields
        .values()
        .filter(|field| {
            matches!(field, FieldAst::Relation(rel)
                if rel.target == target && matches!(rel.cardinality, RelationCardinality::BelongsTo))
        })
        .count()
}

/// Whether `name` is one of `model`'s columns.
fn is_column(model: &ModelAst, name: &str) -> bool {
    model.fields.iter().any(|(field_name, field)| {
        column_names_for(field_name, field)
            .iter()
            .any(|c| c == name)
    })
}

/// The `DO` block that writes each key's directive where its comment does not already hold it.
/// Empty when no key has a name to give.
pub fn graphql_names_sql(ast: &SchemaAst, schema: &str) -> String {
    let rows: Vec<String> = relation_names(ast)
        .iter()
        .filter_map(|names| {
            let directive = names.directive()?;
            Some(format!(
                "({}, {}, {})",
                quote_literal(&quote_qualified(schema, &names.table)),
                quote_literal(&names.column),
                quote_literal(&format!("@graphql({directive})"))
            ))
        })
        .collect();
    if rows.is_empty() {
        return String::new();
    }
    format!("{DO_HEAD}{}{DO_TAIL}", rows.join(",\n      "))
}

/// The block's dollar tag, by which a statement's attribution knows it.
pub const TAG: &str = "graphql_names";

/// Up to the `VALUES` rows: each key's table, column and directive line.
const DO_HEAD: &str = "DO $graphql_names$
DECLARE
  k record;
  wanted text;
BEGIN
  FOR k IN
    SELECT c.conname, c.conrelid::regclass AS rel,
           obj_description(c.oid, 'pg_constraint') AS old, d.directive
    FROM (VALUES
      ";

/// After the rows: the key found by its table and column, whatever it is called, and its comment
/// rewritten only when the directive line is not already its last.
const DO_TAIL: &str = r"
    ) AS d(rel, col, directive)
    JOIN pg_constraint c ON c.conrelid = to_regclass(d.rel) AND c.contype = 'f'
    JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attname = d.col
     AND c.conkey = ARRAY[a.attnum]
  LOOP
    SELECT concat_ws(E'\n', string_agg(l.line, E'\n' ORDER BY l.n), k.directive) INTO wanted
      FROM regexp_split_to_table(k.old, E'\n') WITH ORDINALITY AS l(line, n)
     WHERE l.line NOT LIKE '@graphql(%';
    IF wanted IS DISTINCT FROM k.old THEN
      EXECUTE format('COMMENT ON CONSTRAINT %I ON %s IS %L', k.conname, k.rel, wanted);
    END IF;
  END LOOP;
END
$graphql_names$;";

#[cfg(test)]
mod tests {
    use super::*;

    fn ast(talk_fields: &str, speaker_fields: &str) -> SchemaAst {
        let id = r#""id": { "kind": "uuid", "required": true, "primaryKey": true }"#;
        let doc = format!(
            r#"{{ "astVersion": 2, "models": [
              {{ "name": "Speaker", "annotations": {{ "db": {{ "tableName": "speaker" }} }},
                 "fields": {{ {id}{speaker_fields} }} }},
              {{ "name": "Talk", "annotations": {{ "db": {{ "tableName": "talk" }} }},
                 "fields": {{ {id}{talk_fields} }} }}
            ] }}"#
        );
        crate::parser::parse(&doc).expect("fixture parses")
    }

    const SPEAKER: &str =
        r#", "speaker": { "kind": "relation", "cardinality": "belongsTo", "target": "Speaker" }"#;
    const TALKS: &str =
        r#", "talks": { "kind": "relation", "cardinality": "hasMany", "target": "Talk" }"#;
    const HOST: &str =
        r#", "host": { "kind": "relation", "cardinality": "belongsTo", "target": "Speaker" }"#;

    #[test]
    fn a_key_takes_both_names_the_schema_declared() {
        let names = relation_names(&ast(SPEAKER, TALKS));
        assert_eq!(
            names,
            vec![RelationNames {
                table: "talk".into(),
                column: "speaker_id".into(),
                foreign_table: "speaker".into(),
                foreign_column: "id".into(),
                forward: Some("speaker".into()),
                reverse: Some("talks".into()),
                reverse_is_one: false,
            }]
        );
    }

    #[test]
    fn a_view_leaves_a_has_one_reverse_to_pg_graphql() {
        let profile =
            r#", "profile": { "kind": "relation", "cardinality": "hasOne", "target": "Talk" }"#;
        let names = relation_names(&ast(SPEAKER, profile));
        assert_eq!(names[0].reverse.as_deref(), Some("profile"));
        assert!(names[0].reverse_is_one);
        let both = serde_json::json!({ "foreign_name": "speaker", "local_name": "profile" });
        assert_eq!(names[0].directive(), Some(both));
        let forward = serde_json::json!({ "foreign_name": "speaker" });
        assert_eq!(names[0].view_directive(), Some(forward));
    }

    #[test]
    fn a_reverse_nobody_declared_is_left_to_pg_graphql() {
        let names = relation_names(&ast(SPEAKER, ""));
        assert_eq!(names[0].reverse, None);
        let directive = names[0].directive().expect("the forward name");
        assert_eq!(directive, serde_json::json!({ "foreign_name": "speaker" }));
    }

    #[test]
    fn two_keys_to_one_model_name_no_reverse_they_cannot_tell_apart() {
        let both = format!("{SPEAKER}{HOST}");
        let names = relation_names(&ast(&both, TALKS));
        assert_eq!(names.len(), 2);
        assert!(names.iter().all(|n| n.reverse.is_none()), "{names:?}");
    }

    #[test]
    fn the_block_names_each_key_by_its_table_and_column() {
        let sql = graphql_names_sql(&ast(SPEAKER, TALKS), "public");
        assert!(sql.starts_with(&format!("DO ${TAG}$\n")), "{sql}");
        let row = r#"('"public"."talk"', 'speaker_id', '@graphql({"foreign_name":"speaker","local_name":"talks"})')"#;
        assert!(sql.contains(row), "{sql}");
        assert!(sql.ends_with(&format!("${TAG}$;")), "{sql}");
    }

    #[test]
    fn a_schema_without_keys_writes_nothing() {
        assert_eq!(graphql_names_sql(&ast("", ""), "public"), "");
    }
}
