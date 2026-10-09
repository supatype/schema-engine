//! The description a seed builder is generated from, with no language in it.
//!
//! Seven SDKs need the same facts about a model before any of them can emit a builder:
//! which columns exist, which are optional on insert, which sets of columns are unique
//! enough to be an `ON CONFLICT` target, and which fields are relations to what. Deriving
//! those seven times from [`SchemaAst`] is how the seven drift apart, so they are derived
//! once here and rendered per language.
//!
//! **This file must contain no TypeScript.** It is the thing that makes the six
//! follow-up languages cheap; a `string | null` in here would make each of them a fresh
//! reading of the AST instead.
//!
//! A column carries its originating [`FieldAst`] in `source` when it has one. That is not
//! a leak of a language: it is the schema's own type, and a renderer that can express more
//! than [`ScalarKind`] does (a TypeScript blocks union, say) should not have to re-find
//! the field to do it. Columns that come from a composite (`Timestamps`, `Publishable`,
//! `SoftDelete`) have no field of their own and carry `None`.

use crate::parser::accessors::db_foreign_key;
use crate::parser::ast::{FieldAst, ModelAst, RelationCardinality, SchemaAst};
use std::collections::BTreeSet;

/// The broad shape of a column, in terms every language has.
///
/// Deliberately coarser than [`FieldAst`]: a builder needs to know that a column holds an
/// exact decimal, not that it was declared `Money` rather than `Decimal<19, 4>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarKind {
    Text,
    Uuid,
    /// Fits in a 32-bit integer.
    Integer,
    /// Does not. Rendered as the language's big-integer type, never as a float.
    BigInteger,
    /// Binary floating point, where that is genuinely what the column holds.
    Float,
    /// `NUMERIC`. Exact, and never a float in any language.
    Decimal,
    Boolean,
    /// A point in time.
    Timestamp,
    /// A calendar day, with no time.
    Date,
    Interval,
    Json,
    /// A closed set of strings, listed in [`SeedColumn::enum_values`].
    Enum,
    Binary,
    RichText,
    /// A reference into a storage bucket.
    Storage,
    Geo,
    Vector,
    /// A structured document the schema describes but this enum does not.
    Structured,
}

impl ScalarKind {
    /// The name a generator prints when it needs one, and the manifest key.
    pub fn as_str(self) -> &'static str {
        match self {
            ScalarKind::Text => "text",
            ScalarKind::Uuid => "uuid",
            ScalarKind::Integer => "integer",
            ScalarKind::BigInteger => "bigInteger",
            ScalarKind::Float => "float",
            ScalarKind::Decimal => "decimal",
            ScalarKind::Boolean => "boolean",
            ScalarKind::Timestamp => "timestamp",
            ScalarKind::Date => "date",
            ScalarKind::Interval => "interval",
            ScalarKind::Json => "json",
            ScalarKind::Enum => "enum",
            ScalarKind::Binary => "binary",
            ScalarKind::RichText => "richText",
            ScalarKind::Storage => "storage",
            ScalarKind::Geo => "geo",
            ScalarKind::Vector => "vector",
            ScalarKind::Structured => "structured",
        }
    }

    /// Whether a value of this kind must not round-trip through a binary float.
    ///
    /// The one question every SDK asks of a kind, and the one whose wrong answer is
    /// silent: a `NUMERIC(19,4)` read as a double is still a number, just not the one the
    /// column holds.
    pub fn is_exact_numeric(self) -> bool {
        matches!(self, ScalarKind::Decimal | ScalarKind::BigInteger)
    }

    /// Whether a time operand (`now`, `after`, `before`, `startOf`) may be written here.
    pub fn is_temporal(self) -> bool {
        matches!(self, ScalarKind::Timestamp | ScalarKind::Date)
    }
}

/// One writable column.
#[derive(Debug, Clone)]
pub struct SeedColumn {
    /// The column name, which for a relation's foreign key is the key, not the field.
    pub name: String,
    pub kind: ScalarKind,
    /// True when the column holds an array of `kind`.
    pub array: bool,
    /// Accepts SQL `NULL`.
    pub nullable: bool,
    /// Has a database default, or is filled by the server.
    pub has_default: bool,
    /// May be left out of an insert: it is nullable, defaulted, or server-generated.
    pub optional_on_insert: bool,
    /// The members, for [`ScalarKind::Enum`]. Empty otherwise.
    pub enum_values: Vec<String>,
    /// Stored as a locale map rather than a bare value.
    pub localized: bool,
    /// The model this column is a foreign key to, when it is one.
    ///
    /// What lets a generator type the column so a reference to the wrong model does not
    /// compile, rather than typing every id as a bare string.
    pub references: Option<String>,
    /// The column on that model the key points at, which is `id` unless the relation
    /// named another. Carried beside `references` because a reference to the right model
    /// but the wrong column is the same mistake one level down.
    pub references_column: Option<String>,
    /// The declaration this column came from, absent for composite-expanded columns.
    pub source: Option<FieldAst>,
}

/// How a relation is shaped from this model's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationKind {
    /// The foreign key is a column on this table.
    BelongsTo,
    HasOne,
    HasMany,
    ManyToMany,
}

impl RelationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RelationKind::BelongsTo => "belongsTo",
            RelationKind::HasOne => "hasOne",
            RelationKind::HasMany => "hasMany",
            RelationKind::ManyToMany => "manyToMany",
        }
    }

    /// True when the relation may hold more than one row on the far side.
    pub fn is_collection(self) -> bool {
        matches!(self, RelationKind::HasMany | RelationKind::ManyToMany)
    }
}

/// One relation, from this model's side.
#[derive(Debug, Clone)]
pub struct SeedRelation {
    /// The field name as declared, which is what a nested write is keyed on.
    pub field: String,
    /// The model on the far side.
    pub target: String,
    pub kind: RelationKind,
    /// The foreign key column. On this table for `BelongsTo`, on the target's otherwise.
    ///
    /// `None` when the far side does not declare a matching relation, or declares more
    /// than one and the pairing is therefore ambiguous. A generator that guessed would
    /// produce a nested write that inserts into the wrong column.
    pub foreign_key: Option<String>,
    /// The field on the target that points back here, when exactly one does.
    ///
    /// A nested `create` supplies this side itself, so the far model's shape must have it
    /// removed rather than demanded.
    pub back_reference: Option<String>,
    /// The foreign key is `NOT NULL`.
    pub required: bool,
}

/// A set of columns that identifies at most one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedUniqueKey {
    pub columns: Vec<String>,
}

/// One model, as a seed builder needs it.
#[derive(Debug, Clone)]
pub struct SeedModel {
    /// The name in the schema, and the name an IR operation carries.
    pub name: String,
    /// The table, and the name the builder exposes the model under.
    pub table: String,
    pub columns: Vec<SeedColumn>,
    pub relations: Vec<SeedRelation>,
    /// Every way to name one row, single columns first.
    ///
    /// Empty for a model with no unique column at all, which is a model `upsert` cannot
    /// target. A generator should make that a type error rather than a runtime one.
    pub unique_keys: Vec<SeedUniqueKey>,
}

impl SeedModel {
    pub fn column(&self, name: &str) -> Option<&SeedColumn> {
        self.columns.iter().find(|c| c.name == name)
    }
}

/// Every model, plus the fingerprint the IR must carry.
#[derive(Debug, Clone)]
pub struct SeedSchema {
    /// The schema fingerprint a generated builder stamps into every IR it produces.
    pub fingerprint: String,
    pub models: Vec<SeedModel>,
}

/// Describe `ast` for a seed builder generator.
pub fn describe(ast: &SchemaAst) -> SeedSchema {
    SeedSchema {
        fingerprint: crate::seed::fingerprint::fingerprint(ast),
        models: ast.models.iter().map(|m| describe_model(ast, m)).collect(),
    }
}

fn describe_model(ast: &SchemaAst, model: &ModelAst) -> SeedModel {
    let columns = columns_of(ast, model);
    SeedModel {
        name: model.name.clone(),
        table: model.table_name().to_string(),
        unique_keys: unique_keys_of(model, &columns),
        relations: relations_of(ast, model),
        columns,
    }
}

// ─── Columns ─────────────────────────────────────────────────────────────────

fn columns_of(ast: &SchemaAst, model: &ModelAst) -> Vec<SeedColumn> {
    let mut columns: Vec<SeedColumn> = Vec::new();

    for (name, field) in &model.fields {
        match field {
            FieldAst::Relation(relation) => {
                // Only the `belongsTo` side puts a column on this table, and that column
                // is the foreign key: `organiser_id` holding an id, not `organiser`
                // holding a row.
                if !matches!(relation.cardinality, RelationCardinality::BelongsTo) {
                    continue;
                }
                let Some(key) = db_foreign_key(field, name) else {
                    continue;
                };
                // When the key is also declared as a scalar field in its own right, that
                // declaration is the column and this would be a duplicate of it.
                if model
                    .fields
                    .get(key.as_str())
                    .is_some_and(|f| !matches!(f, FieldAst::Relation(_)))
                {
                    continue;
                }
                columns.push(SeedColumn {
                    name: key,
                    kind: ScalarKind::Uuid,
                    array: false,
                    nullable: !relation.required,
                    has_default: false,
                    optional_on_insert: !relation.required,
                    enum_values: Vec::new(),
                    localized: false,
                    references: Some(relation.target.clone()),
                    references_column: Some(
                        relation
                            .references
                            .clone()
                            .unwrap_or_else(|| "id".to_string()),
                    ),
                    source: Some(field.clone()),
                });
            }
            FieldAst::Timestamps => {
                columns.extend(timestamp_columns(true, true));
            }
            FieldAst::Publishable => columns.extend(publishable_columns()),
            FieldAst::SoftDelete => columns.push(soft_delete_column()),
            scalar => columns.push(scalar_column(ast, model, name, scalar)),
        }
    }

    // The composites again, this time from model options rather than from a field. Both
    // spellings exist and a schema may use either, so both are expanded, and neither may
    // produce a column the other already did.
    if model.options.timestamps {
        let created = !columns.iter().any(|c| c.name == "created_at");
        let updated = !columns.iter().any(|c| c.name == "updated_at");
        columns.extend(timestamp_columns(created, updated));
    }
    if model.options.soft_delete && !columns.iter().any(|c| c.name == "deleted_at") {
        columns.push(soft_delete_column());
    }

    columns
}

fn scalar_column(ast: &SchemaAst, model: &ModelAst, name: &str, field: &FieldAst) -> SeedColumn {
    let (kind, array) = kind_of(field);
    let required = field_required(field);
    let has_default = field_has_default(ast, model, name, field);
    SeedColumn {
        name: name.to_string(),
        kind,
        array,
        nullable: !required,
        has_default,
        optional_on_insert: has_default || !required,
        enum_values: enum_values_of(field),
        localized: crate::parser::accessors::is_localized(field),
        references: None,
        references_column: None,
        source: Some(field.clone()),
    }
}

/// Columns a composite expands to, all of them defaulted by the database.
fn timestamp_columns(created: bool, updated: bool) -> Vec<SeedColumn> {
    let mut out = Vec::new();
    for (name, wanted) in [("created_at", created), ("updated_at", updated)] {
        if wanted {
            out.push(generated_column(name, ScalarKind::Timestamp, false));
        }
    }
    out
}

fn publishable_columns() -> Vec<SeedColumn> {
    let mut status = generated_column("status", ScalarKind::Enum, false);
    status.enum_values = ["draft", "published", "scheduled", "archived"]
        .iter()
        .map(|v| v.to_string())
        .collect();
    vec![
        status,
        generated_column("published_at", ScalarKind::Timestamp, true),
        generated_column("scheduled_at", ScalarKind::Timestamp, true),
    ]
}

fn soft_delete_column() -> SeedColumn {
    generated_column("deleted_at", ScalarKind::Timestamp, true)
}

fn generated_column(name: &str, kind: ScalarKind, nullable: bool) -> SeedColumn {
    SeedColumn {
        name: name.to_string(),
        kind,
        array: false,
        nullable,
        has_default: true,
        optional_on_insert: true,
        enum_values: Vec::new(),
        localized: false,
        references: None,
        references_column: None,
        source: None,
    }
}

// ─── Relations ───────────────────────────────────────────────────────────────

fn relations_of(ast: &SchemaAst, model: &ModelAst) -> Vec<SeedRelation> {
    let mut out = Vec::new();

    for (name, field) in &model.fields {
        let FieldAst::Relation(relation) = field else {
            continue;
        };
        let kind = match relation.cardinality {
            RelationCardinality::BelongsTo => RelationKind::BelongsTo,
            RelationCardinality::HasOne => RelationKind::HasOne,
            RelationCardinality::HasMany => RelationKind::HasMany,
            RelationCardinality::ManyToMany => RelationKind::ManyToMany,
        };

        let (foreign_key, back_reference) = match kind {
            RelationKind::BelongsTo => (db_foreign_key(field, name), None),
            // The key is on the far side, so it is the far side that names it. A
            // many-to-many has no single key at all: its rows live in a junction table.
            RelationKind::ManyToMany => (None, None),
            _ => match back_pointer(ast, &relation.target, &model.name) {
                Some((field_name, key)) => (key, Some(field_name)),
                None => (None, None),
            },
        };

        out.push(SeedRelation {
            field: name.clone(),
            target: relation.target.clone(),
            kind,
            foreign_key,
            back_reference,
            required: relation.required,
        });
    }

    out
}

/// The one `belongsTo` on `target` that points at `owner`, and the column it uses.
///
/// `None` when there is no such relation or more than one: with two, a nested write could
/// not tell which column it is filling, and picking the first would put rows in the wrong
/// one silently.
fn back_pointer(ast: &SchemaAst, target: &str, owner: &str) -> Option<(String, Option<String>)> {
    let model = ast.models.iter().find(|m| m.name == target)?;
    let mut found: Option<(String, Option<String>)> = None;

    for (name, field) in &model.fields {
        let FieldAst::Relation(relation) = field else {
            continue;
        };
        if relation.target != owner
            || !matches!(relation.cardinality, RelationCardinality::BelongsTo)
        {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some((name.clone(), db_foreign_key(field, name)));
    }

    found
}

// ─── Unique keys ─────────────────────────────────────────────────────────────

fn unique_keys_of(model: &ModelAst, columns: &[SeedColumn]) -> Vec<SeedUniqueKey> {
    let mut singles: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    let remember = |column: &str, seen: &mut BTreeSet<String>, singles: &mut Vec<String>| {
        if seen.insert(column.to_string()) {
            singles.push(column.to_string());
        }
    };

    for (name, field) in &model.fields {
        if let FieldAst::Relation(relation) = field {
            // A `hasOne` on the far side makes this table's foreign key unique, which is
            // what lets an upsert target it.
            if relation.unique_fk {
                if let Some(key) = db_foreign_key(field, name) {
                    remember(&key, &mut seen, &mut singles);
                }
            }
            continue;
        }
        if crate::parser::accessors::db_unique(field) || is_primary_key(field) {
            remember(name, &mut seen, &mut singles);
        }
    }

    let mut composites: Vec<SeedUniqueKey> = Vec::new();
    for declared in model.indexes() {
        if !declared.unique {
            continue;
        }
        if declared.fields.len() == 1 {
            remember(&declared.fields[0], &mut seen, &mut singles);
        } else {
            let key = SeedUniqueKey {
                columns: declared.fields.clone(),
            };
            if !composites.contains(&key) {
                composites.push(key);
            }
        }
    }

    // A key naming a column this model does not have would generate a `where` shape that
    // cannot be satisfied. Dropping it here is better than emitting it and letting the
    // author discover it as an unassignable object literal.
    let known = |column: &String| columns.iter().any(|c| &c.name == column);

    let mut keys: Vec<SeedUniqueKey> = singles
        .into_iter()
        .filter(|c| known(c))
        .map(|column| SeedUniqueKey {
            columns: vec![column],
        })
        .collect();
    keys.extend(
        composites
            .into_iter()
            .filter(|key| key.columns.iter().all(known)),
    );
    keys
}

// ─── Reading a field ─────────────────────────────────────────────────────────

/// Read a flag that may sit at the top level or under `annotations.db`.
///
/// The CLI writes `unique` and `serverGenerated` under `annotations.db` while `required`
/// is top level. Reading one place only is how every unique column once looked
/// non-unique, so both are read.
fn json_flag(field: &FieldAst, key: &str) -> bool {
    let value = serde_json::to_value(field).unwrap_or(serde_json::Value::Null);
    let at = |v: &serde_json::Value| v.get(key).and_then(|f| f.as_bool()).unwrap_or(false);
    at(&value)
        || value
            .get("annotations")
            .and_then(|a| a.get("db"))
            .map(at)
            .unwrap_or(false)
}

fn is_primary_key(field: &FieldAst) -> bool {
    json_flag(field, "primaryKey")
}

fn field_required(field: &FieldAst) -> bool {
    json_flag(field, "required")
}

/// Whether the database fills this column when an insert leaves it out.
///
/// Three separate ways that happens, and missing any of them makes a column look required
/// when it is not: a declared default, a server-generated value, and the model's own
/// primary key, which the engine gives `gen_random_uuid()`.
fn field_has_default(ast: &SchemaAst, model: &ModelAst, name: &str, field: &FieldAst) -> bool {
    let value = serde_json::to_value(field).unwrap_or(serde_json::Value::Null);
    if value.get("default").is_some_and(|d| !d.is_null()) {
        return true;
    }
    if json_flag(field, "serverGenerated") || json_flag(field, "readOnly") {
        return true;
    }
    if matches!(field, FieldAst::Slug(_)) || crate::parser::accessors::database_fills(field) {
        return true;
    }
    is_primary_key(field)
        && matches!(field, FieldAst::Uuid(_))
        && primary_key_of(ast, model) == name
}

/// The model's primary key column, which is `id` unless a field claims the role.
fn primary_key_of(ast: &SchemaAst, model: &ModelAst) -> String {
    let _ = ast;
    model
        .fields
        .iter()
        .find(|(_, field)| is_primary_key(field))
        .map(|(name, _)| name.clone())
        .unwrap_or_else(|| "id".to_string())
}

fn enum_values_of(field: &FieldAst) -> Vec<String> {
    match field {
        FieldAst::Enum(e) => e.values.clone(),
        _ => Vec::new(),
    }
}

/// The kind of a scalar field, and whether it is an array of that kind.
fn kind_of(field: &FieldAst) -> (ScalarKind, bool) {
    match field {
        FieldAst::Text(_)
        | FieldAst::Color(_)
        | FieldAst::Email(_)
        | FieldAst::Url(_)
        | FieldAst::Ip(_)
        | FieldAst::Cidr(_)
        | FieldAst::Macaddr(_)
        | FieldAst::Xml(_)
        | FieldAst::Slug(_)
        | FieldAst::TsQuery(_)
        | FieldAst::TsVector(_) => (ScalarKind::Text, false),
        FieldAst::Uuid(_) => (ScalarKind::Uuid, false),
        FieldAst::Bytes(_) => (ScalarKind::Binary, false),
        FieldAst::RichText(_) => (ScalarKind::RichText, false),
        FieldAst::Integer(_) | FieldAst::SmallInt(_) | FieldAst::Serial(_) => {
            (ScalarKind::Integer, false)
        }
        FieldAst::BigInt(_) | FieldAst::BigSerial(_) => (ScalarKind::BigInteger, false),
        FieldAst::Float(_) => (ScalarKind::Float, false),
        // The two exact kinds. Grouping either with `Float` is how a currency amount
        // reaches a caller as an IEEE-754 double.
        FieldAst::Money(_) | FieldAst::Decimal(_) => (ScalarKind::Decimal, false),
        FieldAst::Boolean(_) => (ScalarKind::Boolean, false),
        FieldAst::Datetime(_) | FieldAst::Timestamp(_) => (ScalarKind::Timestamp, false),
        FieldAst::Date(_) => (ScalarKind::Date, false),
        FieldAst::Interval(_) => (ScalarKind::Interval, false),
        FieldAst::Enum(_) => (ScalarKind::Enum, false),
        FieldAst::Json(_) => (ScalarKind::Json, false),
        FieldAst::Button(_) | FieldAst::Blocks(_) => (ScalarKind::Structured, false),
        FieldAst::Geo(_) => (ScalarKind::Geo, false),
        FieldAst::Vector(_) => (ScalarKind::Vector, false),
        FieldAst::Image(_) | FieldAst::File(_) => (ScalarKind::Storage, false),
        FieldAst::Custom(_) => (ScalarKind::Structured, false),
        FieldAst::Array(array) => (element_kind(&array.element_type), true),
        // Composites never reach here: they are expanded into real columns first, and a
        // relation is not a scalar at all.
        FieldAst::Relation(_)
        | FieldAst::Timestamps
        | FieldAst::Publishable
        | FieldAst::SoftDelete => (ScalarKind::Structured, false),
    }
}

/// An array's element kind, read from the Postgres type name the CLI recorded.
fn element_kind(element: &str) -> ScalarKind {
    match element.to_lowercase().as_str() {
        "integer" | "int4" | "int" | "smallint" | "int2" => ScalarKind::Integer,
        "bigint" | "int8" => ScalarKind::BigInteger,
        "float" | "double precision" | "float8" | "real" | "float4" => ScalarKind::Float,
        "numeric" | "decimal" | "money" => ScalarKind::Decimal,
        "boolean" | "bool" => ScalarKind::Boolean,
        "uuid" => ScalarKind::Uuid,
        "timestamptz" | "timestamp" | "timestamp with time zone" => ScalarKind::Timestamp,
        "date" => ScalarKind::Date,
        "jsonb" | "json" => ScalarKind::Json,
        _ => ScalarKind::Text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ast::SchemaAst;

    const SCHEMA: &str = r#"{
        "astVersion": 2,
        "models": [
            {
                "name": "Organiser",
                "fields": {
                    "id": {"kind": "uuid", "required": true, "primaryKey": true},
                    "slug": {"kind": "text", "required": true, "annotations": {"db": {"unique": true}}},
                    "name": {"kind": "text", "required": true},
                    "tier": {"kind": "enum", "required": true, "values": ["free", "pro"], "default": "free"},
                    "commission": {"kind": "money", "required": false},
                    "events": {"kind": "relation", "cardinality": "hasMany", "target": "Event"}
                },
                "options": {"timestamps": true},
                "annotations": {"db": {"tableName": "organiser"}}
            },
            {
                "name": "Event",
                "fields": {
                    "id": {"kind": "uuid", "required": true, "primaryKey": true},
                    "slug": {"kind": "text", "required": true, "annotations": {"db": {"unique": true}}},
                    "title": {"kind": "text", "required": true},
                    "starts_at": {"kind": "datetime", "required": true},
                    "capacity": {"kind": "integer", "required": false},
                    "organiser": {
                        "kind": "relation", "cardinality": "belongsTo", "target": "Organiser",
                        "required": true, "annotations": {"db": {"foreignKey": "organiser_id"}}
                    }
                },
                "annotations": {
                    "db": {
                        "tableName": "event",
                        "indexes": [{"fields": ["organiser_id", "title"], "unique": true, "using": "btree"}]
                    }
                }
            }
        ]
    }"#;

    fn described() -> SeedSchema {
        let ast: SchemaAst = serde_json::from_str(SCHEMA).expect("the fixture parses");
        describe(&ast)
    }

    fn model(schema: &SeedSchema, name: &str) -> SeedModel {
        schema
            .models
            .iter()
            .find(|m| m.name == name)
            .unwrap_or_else(|| panic!("no model {name}"))
            .clone()
    }

    #[test]
    fn it_carries_the_fingerprint_the_ir_must_quote() {
        assert!(described().fingerprint.starts_with("sha256:"));
    }

    #[test]
    fn a_model_is_named_and_tabled() {
        let event = model(&described(), "Event");
        assert_eq!(event.name, "Event");
        assert_eq!(event.table, "event");
    }

    /// A `belongsTo` becomes the column it actually occupies, and that column knows what
    /// it points at, which is what lets a generator reject a reference to another model.
    #[test]
    fn a_belongs_to_becomes_its_foreign_key_column() {
        let event = model(&described(), "Event");
        let key = event
            .column("organiser_id")
            .expect("the foreign key column");
        assert_eq!(key.kind, ScalarKind::Uuid);
        assert_eq!(key.references.as_deref(), Some("Organiser"));
        assert_eq!(
            key.references_column.as_deref(),
            Some("id"),
            "a relation that names no column points at the primary key"
        );
        assert!(!key.nullable, "the relation asked for NOT NULL");
        assert!(
            !key.optional_on_insert,
            "a required relation with no default must be supplied"
        );
        assert!(
            event.column("organiser").is_none(),
            "the relation field is not itself a column"
        );
    }

    /// The inverse side puts no column on this table at all.
    #[test]
    fn an_inverse_relation_contributes_no_column() {
        let organiser = model(&described(), "Organiser");
        assert!(organiser.column("events").is_none());
        assert!(organiser.column("events_id").is_none());
    }

    /// The defect this description exists to stop repeating: a column the database fills
    /// must not be demanded on insert. Three ways a column gets one, all of them here.
    #[test]
    fn anything_the_database_fills_is_optional_on_insert() {
        let organiser = model(&described(), "Organiser");
        for name in ["id", "tier", "created_at", "updated_at"] {
            let column = organiser.column(name).unwrap_or_else(|| panic!("{name}"));
            assert!(
                column.optional_on_insert,
                "{name} has a default and must not be demanded"
            );
            assert!(column.has_default, "{name} has a default");
        }
    }

    #[test]
    fn a_required_column_without_a_default_must_be_supplied() {
        let organiser = model(&described(), "Organiser");
        let name = organiser.column("name").expect("name");
        assert!(!name.optional_on_insert);
        assert!(!name.nullable);
    }

    #[test]
    fn a_nullable_column_is_optional_on_insert() {
        let event = model(&described(), "Event");
        let capacity = event.column("capacity").expect("capacity");
        assert!(capacity.nullable);
        assert!(capacity.optional_on_insert);
        assert!(!capacity.has_default, "nullable is not a default");
    }

    /// Money is `NUMERIC(19,4)`. A generator that reads this as a float has lost the
    /// guarantee the column exists to give.
    #[test]
    fn money_is_an_exact_decimal() {
        let organiser = model(&described(), "Organiser");
        let commission = organiser.column("commission").expect("commission");
        assert_eq!(commission.kind, ScalarKind::Decimal);
        assert!(commission.kind.is_exact_numeric());
    }

    #[test]
    fn an_enum_carries_its_members() {
        let organiser = model(&described(), "Organiser");
        let tier = organiser.column("tier").expect("tier");
        assert_eq!(tier.kind, ScalarKind::Enum);
        assert_eq!(tier.enum_values, vec!["free", "pro"]);
    }

    #[test]
    fn timestamps_expand_into_real_columns() {
        let organiser = model(&described(), "Organiser");
        assert!(organiser.column("created_at").is_some());
        assert!(organiser.column("updated_at").is_some());
        assert_eq!(
            organiser.column("created_at").expect("created_at").kind,
            ScalarKind::Timestamp
        );
    }

    #[test]
    fn a_composite_does_not_expand_twice() {
        let organiser = model(&described(), "Organiser");
        let created = organiser
            .columns
            .iter()
            .filter(|c| c.name == "created_at")
            .count();
        assert_eq!(created, 1, "created_at was expanded more than once");
    }

    /// Unique keys are what `upsert` can target, and nothing else is.
    #[test]
    fn unique_keys_are_the_primary_key_and_the_unique_columns() {
        let organiser = model(&described(), "Organiser");
        let keys: Vec<Vec<String>> = organiser
            .unique_keys
            .iter()
            .map(|k| k.columns.clone())
            .collect();
        assert!(keys.contains(&vec!["id".to_string()]), "{keys:?}");
        assert!(keys.contains(&vec!["slug".to_string()]), "{keys:?}");
        assert!(
            !keys.contains(&vec!["name".to_string()]),
            "name is not unique: {keys:?}"
        );
    }

    #[test]
    fn a_unique_composite_index_is_a_key() {
        let event = model(&described(), "Event");
        assert!(
            event
                .unique_keys
                .iter()
                .any(|k| k.columns == vec!["organiser_id".to_string(), "title".to_string()]),
            "{:?}",
            event.unique_keys
        );
    }

    /// The far side of a `hasMany` is where the foreign key lives, and a nested create
    /// needs to know which field on that model points back here.
    #[test]
    fn an_inverse_relation_finds_the_key_on_the_far_side() {
        let organiser = model(&described(), "Organiser");
        let events = organiser
            .relations
            .iter()
            .find(|r| r.field == "events")
            .expect("the events relation");
        assert_eq!(events.kind, RelationKind::HasMany);
        assert!(events.kind.is_collection());
        assert_eq!(events.target, "Event");
        assert_eq!(events.foreign_key.as_deref(), Some("organiser_id"));
        assert_eq!(events.back_reference.as_deref(), Some("organiser"));
    }

    /// Two relations from the same model to the same target cannot be paired, and a guess
    /// would put rows in the wrong column without saying so.
    #[test]
    fn an_ambiguous_back_reference_is_left_unresolved() {
        let ambiguous = SCHEMA.replace(
            r#""capacity": {"kind": "integer", "required": false},"#,
            r#""capacity": {"kind": "integer", "required": false},
               "co_organiser": {
                   "kind": "relation", "cardinality": "belongsTo", "target": "Organiser",
                   "required": false, "annotations": {"db": {"foreignKey": "co_organiser_id"}}
               },"#,
        );
        let ast: SchemaAst = serde_json::from_str(&ambiguous).expect("parses");
        let schema = describe(&ast);
        let organiser = model(&schema, "Organiser");
        let events = organiser
            .relations
            .iter()
            .find(|r| r.field == "events")
            .expect("events");
        assert_eq!(events.foreign_key, None);
        assert_eq!(events.back_reference, None);
    }

    #[test]
    fn a_belongs_to_relation_names_its_own_key() {
        let event = model(&described(), "Event");
        let organiser = event
            .relations
            .iter()
            .find(|r| r.field == "organiser")
            .expect("organiser");
        assert_eq!(organiser.kind, RelationKind::BelongsTo);
        assert!(!organiser.kind.is_collection());
        assert_eq!(organiser.foreign_key.as_deref(), Some("organiser_id"));
        assert!(organiser.required);
    }

    #[test]
    fn a_temporal_column_accepts_a_time_operand_and_a_text_one_does_not() {
        let event = model(&described(), "Event");
        assert!(event
            .column("starts_at")
            .expect("starts_at")
            .kind
            .is_temporal());
        assert!(!event.column("title").expect("title").kind.is_temporal());
    }
}
