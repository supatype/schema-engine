//! Naming conventions for the objects Supatype creates, and the one thing left of its comment stamps:
//! recognising and removing an older engine's `supatype:managed` stamp (plan section 7). Since Phase
//! 6 nothing writes one; ownership is the ledger's.

use std::collections::{HashMap, HashSet};

use crate::parser::ast::{IndexAst, SchemaAst};

pub const MANAGED_PREFIX: &str = "supatype:managed";

/// Returns true when a Postgres object comment marks it as Supatype-managed.
pub fn is_managed_comment(comment: Option<&str>) -> bool {
    comment
        .map(|c| c.starts_with(MANAGED_PREFIX))
        .unwrap_or(false)
}

/// `comment` with the stamp line taken out: `None` when the comment was only the stamp, the
/// remaining lines otherwise. Once an object is in the ledger its comment is the user's (plan
/// section 6), so whatever they wrote beside the stamp stays.
pub fn comment_without_stamp(comment: Option<&str>) -> Option<String> {
    let rest: Vec<&str> = comment?
        .lines()
        .filter(|line| !line.starts_with(MANAGED_PREFIX))
        .collect();
    let rest = rest.join("\n");
    (!rest.trim().is_empty()).then_some(rest)
}

/// Postgres's identifier limit: `NAMEDATALEN - 1` bytes.
pub const MAX_IDENTIFIER_BYTES: usize = 63;

/// Postgres's `NAMEDATALEN`.
const NAMEDATALEN: usize = MAX_IDENTIFIER_BYTES + 1;

/// The longest prefix of `s` that fits in `limit` bytes without splitting a character: Postgres's
/// `pg_mbcliplen` for UTF-8.
fn clip(s: &str, limit: usize) -> &str {
    if s.len() <= limit {
        return s;
    }
    let mut cut = limit;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

/// A name as Postgres stores it: anything past 63 bytes is cut off, on a character boundary
/// (`truncate_identifier` in Postgres's `scansup.c`). For a name the schema states outright, such
/// as a declared index's.
pub fn clip_identifier(name: &str) -> String {
    clip(name, MAX_IDENTIFIER_BYTES).to_string()
}

/// Postgres's `makeObjectName`: `name1_name2_label`, fitted to the identifier limit the way
/// Postgres fits the names it chooses itself.
///
/// The label is always kept whole. When the rest does not fit, the longer of `name1` and `name2`
/// gives up a byte at a time (`name2` on a tie) until both fit, and each is then cut back to a
/// character boundary. So `organization_membership_invitations` with
/// `notification_preference_email` keeps the whole column and loses the end of the table, and
/// the same table's `notification_preference_phone` stays a different name. Matching Postgres
/// byte for byte is the point: a name built any other way is one nothing that knows Postgres can
/// predict.
pub fn make_object_name(name1: &str, name2: Option<&str>, label: &str) -> String {
    let mut overhead = 0;
    if name2.is_some() {
        overhead += 1; // the underscore between the names
    }
    if !label.is_empty() {
        overhead += label.len() + 1;
    }
    let available = MAX_IDENTIFIER_BYTES.saturating_sub(overhead);
    let mut name1_bytes = name1.len();
    let mut name2_bytes = name2.map_or(0, str::len);
    while name1_bytes + name2_bytes > available {
        if name1_bytes > name2_bytes {
            name1_bytes -= 1;
        } else {
            name2_bytes -= 1;
        }
    }
    let mut out = clip(name1, name1_bytes).to_string();
    if let Some(name2) = name2 {
        out.push('_');
        out.push_str(clip(name2, name2_bytes));
    }
    if !label.is_empty() {
        out.push('_');
        out.push_str(label);
    }
    out
}

/// Postgres's `ChooseIndexNameAddition` (and `ChooseForeignKeyConstraintNameAddition`): the
/// column names joined with underscores, stopping once the result reaches `NAMEDATALEN` bytes.
pub fn name_addition<S: AsRef<str>>(columns: &[S]) -> String {
    let mut out = String::new();
    for column in columns {
        if !out.is_empty() {
            out.push('_');
        }
        out.push_str(clip(column.as_ref(), MAX_IDENTIFIER_BYTES));
        if out.len() >= NAMEDATALEN {
            break;
        }
    }
    out
}

/// The names already taken in one namespace, and Postgres's way of choosing a free one.
#[derive(Debug, Default, Clone)]
pub struct NameChooser {
    taken: HashSet<String>,
}

impl NameChooser {
    /// Marks `name` taken as it stands: a table's name, or one the schema states outright.
    pub fn claim(&mut self, name: &str) {
        self.taken.insert(name.to_string());
    }

    /// Postgres's `ChooseRelationName` / `ChooseConstraintName`: [`make_object_name`] as it
    /// stands when that name is free, and otherwise with a number appended to the label (`key1`,
    /// `key2`, ...), the name fitted again each time, until one is. The chosen name is then taken.
    pub fn choose(&mut self, name1: &str, name2: Option<&str>, label: &str) -> String {
        let mut pass = 0usize;
        loop {
            let label = if pass == 0 {
                label.to_string()
            } else {
                format!("{label}{pass}")
            };
            let name = make_object_name(name1, name2, &label);
            if self.taken.insert(name.clone()) {
                return name;
            }
            pass += 1;
        }
    }
}

/// Postgres's own default name for a table's primary key, before any collision is resolved.
/// [`ObjectNames::primary_key`] is the one a push uses.
pub fn primary_key_name(table: &str) -> String {
    make_object_name(table, None, "pkey")
}

/// Postgres's own default name for a single-column foreign key, before any collision is resolved.
pub fn foreign_key_name(table: &str, column: &str) -> String {
    make_object_name(table, Some(column), "fkey")
}

/// Postgres's own default name for the check a field type carries (an `Email` regex, a `URL`
/// prefix, a TEXT enum's `IN` list, a `Publishable` status), as distinct from a declared bound.
pub fn type_check_name(table: &str, column: &str) -> String {
    make_object_name(table, Some(column), "check")
}

/// Name for the constraint holding a column's declared bounds.
///
/// Deliberately not Postgres's own `{table}_{column}_check`: an inline `CHECK` written by anything
/// else already claims that name, and a bound Supatype manages has to be distinguishable from one it
/// merely found, or `doctor` and `adopt` cannot tell them apart. Fitted to the limit as Postgres
/// fits its own, with `bounds` for the label.
pub fn expected_check_constraint_name(table: &str, column: &str) -> String {
    make_object_name(table, Some(column), "bounds")
}

/// The label of a model-level constraint, by its position in the declared list.
fn model_constraint_label(index: usize) -> String {
    format!("check_{}", index + 1)
}

/// Name for a model-level constraint, by its position in the declared list.
///
/// Positional because the rule itself has no name: the author writes an expression, not an
/// identifier. Reordering `constraints` therefore renames them, which the differ handles as a drop
/// and an add of the same expression, and the fingerprint in the comment keeps that from churning
/// when nothing actually changed.
pub fn expected_model_constraint_name(table: &str, index: usize) -> String {
    make_object_name(table, None, &model_constraint_label(index))
}

/// Postgres default name for a single-column UNIQUE constraint, before any collision is resolved.
pub fn expected_unique_constraint_name(table: &str, column: &str) -> String {
    make_object_name(table, Some(column), "key")
}

/// Default name for a model-level index (`indexes` in schema meta), before any collision is
/// resolved: Postgres's own for an unnamed `CREATE INDEX`.
pub fn expected_model_index_name(table: &str, fields: &[String]) -> String {
    make_object_name(table, Some(&name_addition(fields)), "idx")
}

/// Name of the index an access rule's join column gets (`idx_{table}_{column}_rls`), fitted to the
/// limit as Postgres fits its own.
pub fn membership_index_name(table: &str, column: &str) -> String {
    make_object_name(&format!("idx_{table}"), Some(column), "rls")
}

/// Name of a policy on `table` (`{table}_{suffix}`), fitted to the limit as Postgres fits its own.
/// Policy names are per table, and the suffixes a table's own policies take are distinct, so these
/// need no collision resolution.
pub fn policy_name(table: &str, suffix: &str) -> String {
    make_object_name(table, None, suffix)
}

/// What one generated name belongs to: the table, the kind of object, and what on the table it
/// covers.
type NameOwner = (String, &'static str, String);

/// Every name a push gives the objects it creates on the schema's model tables, chosen once for the
/// whole schema the way Postgres would choose them had they been left unnamed.
///
/// Postgres keeps index names (a primary key's and a unique constraint's included), sequence names
/// and table names in one namespace per schema, and a clash there is `42P07` on the second
/// `CREATE`. So `order.item_code` and `order_item.code` cannot both have `order_item_code_key`:
/// the first in declaration order keeps it and the second gets `order_item_code_key1`, as Postgres
/// itself would have given it. Check and foreign key names only have to be unique on their table,
/// so they are chosen per table. Tables and the names the schema states outright are claimed
/// first, then the sequences (Postgres names a serial's sequence when it creates the table, before
/// anything else on it), then each model's keys and indexes in declaration order. The desired set
/// and the generator both read their names from here, so what a push creates is what the ledger
/// looks for.
#[derive(Debug, Default, Clone)]
pub struct ObjectNames {
    chosen: HashMap<NameOwner, String>,
}

fn index_owner(index: &IndexAst) -> String {
    format!(
        "{:?}|{}|{}|{}",
        index.name,
        index.fields.join(","),
        index.using.as_sql(),
        index.unique
    )
}

impl ObjectNames {
    pub fn for_schema(ast: &SchemaAst) -> Self {
        use crate::differ::column_diff::field_is_primary_key;
        use crate::generator::sql::migration::{field_check_expression, implicit_model_indexes};
        use crate::parser::accessors::{
            column_names_for, db_foreign_key, db_unique, default_foreign_key_column, versions_of,
            versions_table_name,
        };
        use crate::parser::ast::{FieldAst, RelationCardinality};

        let mut names = ObjectNames::default();
        let mut relations = NameChooser::default();

        for model in &ast.models {
            relations.claim(model.table_name());
            if versions_of(model).is_some() {
                relations.claim(&versions_table_name(model.table_name()));
            }
            for index in model.indexes() {
                if let Some(name) = &index.name {
                    relations.claim(&clip_identifier(name));
                }
            }
        }
        for junction in &ast.junction_tables {
            relations.claim(&junction.name);
        }

        let serial =
            |field: &FieldAst| matches!(field, FieldAst::Serial(_) | FieldAst::BigSerial(_));
        for model in &ast.models {
            let table = model.table_name();
            for (field_name, field) in &model.fields {
                if !serial(field) {
                    continue;
                }
                for column in column_names_for(field_name, field) {
                    let name = relations.choose(table, Some(&column), "seq");
                    names.set(table, "seq", &column, name);
                }
            }
        }

        for model in &ast.models {
            let table = model.table_name();
            if model.fields.values().any(field_is_primary_key) {
                let name = relations.choose(table, None, "pkey");
                names.set(table, "pkey", "", name);
            }
            for (field_name, field) in &model.fields {
                let unique_fk = matches!(
                    field,
                    FieldAst::Relation(rel)
                        if matches!(rel.cardinality, RelationCardinality::BelongsTo) && rel.unique_fk
                );
                let columns = if unique_fk {
                    vec![db_foreign_key(field, field_name)
                        .unwrap_or_else(|| default_foreign_key_column(field_name))]
                } else if db_unique(field) && !matches!(field, FieldAst::Relation(_)) {
                    column_names_for(field_name, field)
                } else {
                    continue;
                };
                for column in columns.into_iter().filter(|c| !c.is_empty()) {
                    if !names
                        .chosen
                        .contains_key(&(table.to_string(), "key", column.clone()))
                    {
                        let name = relations.choose(table, Some(&column), "key");
                        names.set(table, "key", &column, name);
                    }
                }
            }
            for index in model.indexes() {
                if index.name.is_none() {
                    let name = relations.choose(table, Some(&name_addition(&index.fields)), "idx");
                    names.set(table, "index", &index_owner(index), name);
                }
            }
            // The indexes nobody declares: a named one is a Blocks GIN, the rest Postgres's own.
            for index in implicit_model_indexes(model) {
                let label = if index.name.is_some() {
                    "gin_idx"
                } else {
                    "idx"
                };
                let owner = index_owner(&index);
                if !names
                    .chosen
                    .contains_key(&(table.to_string(), "index", owner.clone()))
                {
                    let name = relations.choose(table, Some(&name_addition(&index.fields)), label);
                    names.set(table, "index", &owner, name);
                }
            }
            if model.options.singleton {
                let name = relations.choose(table, None, "singleton_idx");
                names.set(table, "singleton", "", name);
            }
        }
        for junction in &ast.junction_tables {
            let name = relations.choose(&junction.name, None, "pkey");
            names.set(&junction.name, "pkey", "", name);
        }

        // Per table: foreign keys, the checks a field type carries, declared bounds, model rules.
        for model in &ast.models {
            let table = model.table_name();
            let mut constraints = NameChooser::default();
            for (field_name, field) in &model.fields {
                if let FieldAst::Relation(rel) = field {
                    if matches!(rel.cardinality, RelationCardinality::BelongsTo) {
                        let column = db_foreign_key(field, field_name)
                            .unwrap_or_else(|| default_foreign_key_column(field_name));
                        let name = constraints.choose(table, Some(&column), "fkey");
                        names.set(table, "fkey", &column, name);
                    }
                }
            }
            for (field_name, field) in &model.fields {
                let type_check = matches!(
                    field,
                    FieldAst::Email(_)
                        | FieldAst::Url(_)
                        | FieldAst::Enum(_)
                        | FieldAst::Publishable
                );
                let columns = match field {
                    FieldAst::Publishable => vec!["status".to_string()],
                    _ => column_names_for(field_name, field),
                };
                for column in columns.into_iter().filter(|c| !c.is_empty()) {
                    if type_check {
                        let name = constraints.choose(table, Some(&column), "check");
                        names.set(table, "check", &column, name);
                    }
                    if field_check_expression(field, &column).is_some() {
                        let name = constraints.choose(table, Some(&column), "bounds");
                        names.set(table, "bounds", &column, name);
                    }
                }
            }
            for index in 0..model.annotations.db.constraints.len() {
                let label = model_constraint_label(index);
                let name = constraints.choose(table, None, &label);
                names.set(table, "rule", &index.to_string(), name);
            }
        }
        for junction in &ast.junction_tables {
            let mut constraints = NameChooser::default();
            for column in [&junction.fk_a, &junction.fk_b] {
                let name = constraints.choose(&junction.name, Some(column), "fkey");
                names.set(&junction.name, "fkey", column, name);
            }
        }
        names
    }

    fn set(&mut self, table: &str, kind: &'static str, detail: &str, name: String) {
        self.chosen
            .insert((table.to_string(), kind, detail.to_string()), name);
    }

    fn get(&self, table: &str, kind: &'static str, detail: &str) -> Option<String> {
        self.chosen
            .get(&(table.to_string(), kind, detail.to_string()))
            .cloned()
    }

    /// The table's primary key.
    pub fn primary_key(&self, table: &str) -> String {
        self.get(table, "pkey", "")
            .unwrap_or_else(|| primary_key_name(table))
    }

    /// A single-column unique constraint.
    pub fn unique(&self, table: &str, column: &str) -> String {
        self.get(table, "key", column)
            .unwrap_or_else(|| expected_unique_constraint_name(table, column))
    }

    /// A model index, declared or implicit: its stated name as Postgres stores it, or the chosen one.
    pub fn index(&self, table: &str, index: &IndexAst) -> String {
        if let Some(name) = self.get(table, "index", &index_owner(index)) {
            return name;
        }
        match &index.name {
            Some(name) => clip_identifier(name),
            None => expected_model_index_name(table, &index.fields),
        }
    }

    /// A singleton model's one-row index.
    pub fn singleton_index(&self, table: &str) -> String {
        self.get(table, "singleton", "")
            .unwrap_or_else(|| make_object_name(table, None, "singleton_idx"))
    }

    /// The sequence a serial column owns.
    pub fn sequence(&self, table: &str, column: &str) -> String {
        self.get(table, "seq", column)
            .unwrap_or_else(|| make_object_name(table, Some(column), "seq"))
    }

    /// A single-column foreign key.
    pub fn foreign_key(&self, table: &str, column: &str) -> String {
        self.get(table, "fkey", column)
            .unwrap_or_else(|| foreign_key_name(table, column))
    }

    /// The check a field type carries.
    pub fn type_check(&self, table: &str, column: &str) -> String {
        self.get(table, "check", column)
            .unwrap_or_else(|| type_check_name(table, column))
    }

    /// A column's declared bounds.
    pub fn bounds(&self, table: &str, column: &str) -> String {
        self.get(table, "bounds", column)
            .unwrap_or_else(|| expected_check_constraint_name(table, column))
    }

    /// A model-level constraint, by its position in the declared list.
    pub fn model_constraint(&self, table: &str, index: usize) -> String {
        self.get(table, "rule", &index.to_string())
            .unwrap_or_else(|| expected_model_constraint_name(table, index))
    }
}

/// The value side of a `COMMENT ON ... IS`: a quoted literal, or `NULL` to clear it, for the ledger
/// putting back what a user wrote beside a stamp it removes.
pub fn comment_value(text: Option<&str>) -> String {
    match text {
        Some(t) => format!("'{}'", t.replace('\'', "''")),
        None => "NULL".to_string(),
    }
}

/// `COMMENT ON CONSTRAINT`, with `None` clearing the comment.
pub fn comment_on_constraint(
    schema: &str,
    table: &str,
    constraint: &str,
    text: Option<&str>,
) -> String {
    format!(
        "COMMENT ON CONSTRAINT \"{constraint}\" ON \"{schema}\".\"{table}\" IS {};",
        comment_value(text)
    )
}

/// `COMMENT ON TABLE`, with `None` clearing the comment.
pub fn comment_on_table(schema: &str, table: &str, text: Option<&str>) -> String {
    format!(
        "COMMENT ON TABLE \"{schema}\".\"{table}\" IS {};",
        comment_value(text)
    )
}

/// `COMMENT ON INDEX`, with `None` clearing the comment.
pub fn comment_on_index(schema: &str, index: &str, text: Option<&str>) -> String {
    format!(
        "COMMENT ON INDEX \"{schema}\".\"{index}\" IS {};",
        comment_value(text)
    )
}
