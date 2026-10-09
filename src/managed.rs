//! Naming conventions for the objects Supatype creates, and the one thing left of its comment stamps:
//! recognising and removing an older engine's `supatype:managed` stamp (plan section 7). Since Phase
//! 6 nothing writes one; ownership is the ledger's.

use std::collections::{HashMap, HashSet};

use crate::parser::ast::{FieldAst, IndexAst, ModelAst, SchemaAst};

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
        choose_free(&mut [self], name1, name2, label)
    }
}

/// [`NameChooser::choose`] for a name that must be free in every one of `namespaces`, and is then
/// taken in all of them: a primary key's or a unique constraint's, which is an index (a relation)
/// and a constraint at once, as `ChooseRelationName` with `isconstraint` checks both.
fn choose_free(
    namespaces: &mut [&mut NameChooser],
    name1: &str,
    name2: Option<&str>,
    label: &str,
) -> String {
    let mut pass = 0usize;
    loop {
        let label = if pass == 0 {
            label.to_string()
        } else {
            format!("{label}{pass}")
        };
        let name = make_object_name(name1, name2, &label);
        if namespaces.iter().all(|n| !n.taken.contains(&name)) {
            for namespace in namespaces.iter_mut() {
                namespace.taken.insert(name.clone());
            }
            return name;
        }
        pass += 1;
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

/// Name of the index that makes "the newest version of this record" a lookup rather than a scan.
///
/// Every read of a draft goes through it, so it is not optional decoration: the draft view's lateral
/// join orders by `version DESC` and takes one row.
pub fn versions_record_index_name(versions_table: &str) -> String {
    make_object_name(versions_table, None, "record_idx")
}

/// Name of the unique constraint on `(record_id, version)`: Postgres's own for it.
pub fn versions_record_key_name(versions_table: &str) -> String {
    make_object_name(versions_table, Some("record_id_version"), "key")
}

/// Name of a policy on `table` (`{table}_{suffix}`), fitted to the limit as Postgres fits its own.
/// Policy names are per table, and the suffixes a table's own policies take are distinct, so these
/// need no collision resolution.
pub fn policy_name(table: &str, suffix: &str) -> String {
    make_object_name(table, None, suffix)
}

/// The few answers about a model that live in modules the WASM build leaves out (`differ` and
/// `generator::sql`, which pull in sqlx). The WASM build names only indexes and model rules (the
/// admin metadata), and a generated name can collide only with one ending in the same label, so
/// what these decide (primary keys, bounds, trigger functions) never changes those.
#[cfg(not(target_arch = "wasm32"))]
mod engine {
    use crate::parser::ast::{FieldAst, ModelAst};

    pub(super) use crate::differ::column_diff::field_is_primary_key;

    pub(super) fn has_bounds(field: &FieldAst, column: &str) -> bool {
        crate::generator::sql::migration::field_check_expression(field, column).is_some()
    }

    pub(super) fn shared_function_names() -> Vec<String> {
        crate::generator::sql::triggers::shared_functions()
            .into_iter()
            .map(|f| f.name)
            .collect()
    }

    pub(super) fn slug_fields(model: &ModelAst) -> Vec<&str> {
        crate::generator::sql::triggers::slug_fields(model)
            .map(|(name, _)| name.as_str())
            .collect()
    }
}

#[cfg(target_arch = "wasm32")]
mod engine {
    use crate::parser::ast::{FieldAst, ModelAst};

    pub(super) fn field_is_primary_key(_: &FieldAst) -> bool {
        false
    }

    pub(super) fn has_bounds(_: &FieldAst, _: &str) -> bool {
        false
    }

    pub(super) fn shared_function_names() -> Vec<String> {
        Vec::new()
    }

    pub(super) fn slug_fields(_: &ModelAst) -> Vec<&str> {
        Vec::new()
    }
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
/// the first in order of table name keeps it and the second gets `order_item_code_key1`, as
/// Postgres itself would have given it had it created them in that order. Constraint names are chosen as Postgres chooses them too: free of
/// every constraint name in the schema, not only those on the same table, and a primary key or
/// unique constraint, being both an index and a constraint, free in both. Tables, the names the
/// schema states outright and the versions tables' fixed names are claimed first, then the
/// sequences (Postgres names a serial's sequence when it creates the table, before anything else
/// on it), then each model's keys and indexes, then the checks and foreign keys. Never in
/// declaration order: tables go in order of their names, and a table's columns and indexes in
/// order of theirs, so reordering models or fields in the schema renames nothing. Adding a model
/// whose names clash with an existing one's can still move a digit, as it would in Postgres. The functions and triggers a push generates are fitted the same way, with a digit where
/// two would otherwise share a name: trigger names per table, function names per schema (a
/// function taking its table's row type is told apart by that argument and needs none). The
/// desired set and the generator both read their names from here, so what a push creates is what
/// the ledger looks for.
#[derive(Debug, Default, Clone)]
pub struct ObjectNames {
    chosen: HashMap<NameOwner, String>,
}

/// The schema's models in order of their tables' names; models on one table keep their declared
/// order among themselves.
fn sorted_models(ast: &SchemaAst) -> Vec<&ModelAst> {
    let mut models: Vec<&ModelAst> = ast.models.iter().collect();
    models.sort_by(|a, b| a.table_name().cmp(b.table_name()));
    models
}

/// A model's fields in order of their names.
fn sorted_fields(model: &ModelAst) -> Vec<(&String, &FieldAst)> {
    let mut fields: Vec<_> = model.fields.iter().collect();
    fields.sort_by(|a, b| a.0.cmp(b.0));
    fields
}

/// Indexes in order of what they cover.
fn sorted_indexes<'a>(indexes: impl Iterator<Item = &'a IndexAst>) -> Vec<&'a IndexAst> {
    let mut indexes: Vec<&IndexAst> = indexes.collect();
    indexes.sort_by_cached_key(|index| index_owner(index));
    indexes
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
        use crate::parser::accessors::implicit_model_indexes;
        use crate::parser::accessors::{
            column_names_for, db_foreign_key, db_unique, default_foreign_key_column, versions_of,
            versions_table_name,
        };
        use crate::parser::ast::RelationCardinality;

        let mut names = ObjectNames::default();
        // Declaration order decides nothing: the tables are named in order of their names, and
        // each table's columns and indexes in order of theirs, so reordering models or fields
        // renames nothing (a model added with a clashing name still can, as it would in Postgres).
        let models = sorted_models(ast);
        let mut junctions: Vec<_> = ast.junction_tables.iter().collect();
        junctions.sort_by(|a, b| a.name.cmp(&b.name));
        let mut relations = NameChooser::default();
        let mut constraints = NameChooser::default();

        for model in &models {
            relations.claim(model.table_name());
            if versions_of(model).is_some() {
                let vt = versions_table_name(model.table_name());
                relations.claim(&vt);
                for key in [primary_key_name(&vt), versions_record_key_name(&vt)] {
                    relations.claim(&key);
                    constraints.claim(&key);
                }
                relations.claim(&versions_record_index_name(&vt));
                constraints.claim(&foreign_key_name(&vt, "record_id"));
                constraints.claim(&type_check_name(&vt, "status"));
            }
            for index in model.indexes() {
                if let Some(name) = &index.name {
                    relations.claim(&clip_identifier(name));
                }
            }
        }
        for junction in &junctions {
            relations.claim(&junction.name);
        }

        let serial = crate::parser::accessors::owns_sequence;
        for model in &models {
            let table = model.table_name();
            for (field_name, field) in sorted_fields(model) {
                if !serial(field) {
                    continue;
                }
                for column in column_names_for(field_name, field) {
                    names.pick(table, "seq", &column, || {
                        relations.choose(table, Some(&column), "seq")
                    });
                }
            }
        }

        for model in &models {
            let table = model.table_name();
            if model.fields.values().any(engine::field_is_primary_key) {
                names.pick(table, "pkey", "", || {
                    choose_free(&mut [&mut relations, &mut constraints], table, None, "pkey")
                });
            }
            for (field_name, field) in sorted_fields(model) {
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
                    names.pick(table, "key", &column, || {
                        choose_free(
                            &mut [&mut relations, &mut constraints],
                            table,
                            Some(&column),
                            "key",
                        )
                    });
                }
            }
            for index in sorted_indexes(model.indexes().iter()) {
                if index.name.is_none() {
                    names.pick(table, "index", &index_owner(index), || {
                        relations.choose(table, Some(&name_addition(&index.fields)), "idx")
                    });
                }
            }
            // The indexes nobody declares: a named one is a Blocks GIN, the rest Postgres's own.
            let implicit = implicit_model_indexes(model);
            for index in sorted_indexes(implicit.iter()) {
                let label = if index.name.is_some() {
                    "gin_idx"
                } else {
                    "idx"
                };
                names.pick(table, "index", &index_owner(index), || {
                    relations.choose(table, Some(&name_addition(&index.fields)), label)
                });
            }
            if model.options.singleton {
                names.pick(table, "singleton", "", || {
                    relations.choose(table, None, "singleton_idx")
                });
            }
        }
        for junction in &junctions {
            names.pick(&junction.name, "pkey", "", || {
                choose_free(
                    &mut [&mut relations, &mut constraints],
                    &junction.name,
                    None,
                    "pkey",
                )
            });
        }

        // Foreign keys, the checks a field type carries, declared bounds and model rules, each free
        // of every constraint name in the schema.
        for model in &models {
            let table = model.table_name();
            for (field_name, field) in sorted_fields(model) {
                if let FieldAst::Relation(rel) = field {
                    if matches!(rel.cardinality, RelationCardinality::BelongsTo) {
                        let column = db_foreign_key(field, field_name)
                            .unwrap_or_else(|| default_foreign_key_column(field_name));
                        names.pick(table, "fkey", &column, || {
                            constraints.choose(table, Some(&column), "fkey")
                        });
                    }
                }
            }
            for (field_name, field) in sorted_fields(model) {
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
                        names.pick(table, "check", &column, || {
                            constraints.choose(table, Some(&column), "check")
                        });
                    }
                    if engine::has_bounds(field, &column) {
                        names.pick(table, "bounds", &column, || {
                            constraints.choose(table, Some(&column), "bounds")
                        });
                    }
                }
            }
            for index in 0..model.annotations.db.constraints.len() {
                let label = model_constraint_label(index);
                names.pick(table, "rule", &index.to_string(), || {
                    constraints.choose(table, None, &label)
                });
            }
        }
        for junction in &junctions {
            for column in [&junction.fk_a, &junction.fk_b] {
                names.pick(&junction.name, "fkey", column, || {
                    constraints.choose(&junction.name, Some(column), "fkey")
                });
            }
        }
        names.functions_and_triggers(ast);
        names
    }

    /// The generated functions and triggers. A trigger is named on its table, and a function in its
    /// schema; the affordance functions (`can_<op>_<table>`) take their table's row type, which
    /// keeps two of them apart whatever their names, so only their per-column forms, which share
    /// one table's type, take digits.
    fn functions_and_triggers(&mut self, ast: &SchemaAst) {
        use crate::parser::accessors::{versions_of, versions_table_name};

        let mut platform = NameChooser::default();
        for name in engine::shared_function_names() {
            platform.claim(&name);
        }
        let mut helper = NameChooser::default();
        let mut api = NameChooser::default();
        for model in sorted_models(ast) {
            let table = model.table_name();
            let mut triggers = NameChooser::default();
            let lower = table.to_ascii_lowercase();
            self.pick(table, "updated_at_trigger", "", || {
                triggers.choose(table, None, "updated_at_trigger")
            });
            for slug in engine::slug_fields(model) {
                self.pick(table, "slug_function", slug, || {
                    platform.choose(
                        &format!("set_{lower}"),
                        Some(&slug.to_ascii_lowercase()),
                        "",
                    )
                });
                self.pick(table, "slug_trigger", slug, || {
                    triggers.choose(table, Some(slug), "trigger")
                });
            }
            self.pick(table, "rich_text_function", "", || {
                platform.choose(&format!("normalise_{lower}"), None, "rich_text")
            });
            self.pick(table, "rich_text_trigger", "", || {
                triggers.choose(table, None, "rich_text_trigger")
            });
            if versions_of(model).is_some() {
                let vt = versions_table_name(table);
                self.pick(table, "can_edit", "", || {
                    helper.choose("can_edit", Some(table), "")
                });
                self.pick(table, "sees_draft", "", || {
                    helper.choose("sees_draft", Some(table), "")
                });
                self.pick(table, "versions_guard", "", || {
                    helper.choose(&vt, None, "guard")
                });
                // The audit trigger sits on the model's table and shares its function's name.
                self.pick(table, "versions_audit", "", || {
                    choose_free(&mut [&mut helper, &mut triggers], &vt, None, "audit")
                });
            }
            self.pick(table, "write_function", "", || {
                api.choose(table, None, "_write")
            });
            let mut fields = NameChooser::default();
            let mut columns: Vec<&String> = model.access().fields.keys().collect();
            columns.sort();
            for op in ["read", "write"] {
                for column in columns.iter().copied() {
                    self.pick(table, "field_can", &format!("{op}.{column}"), || {
                        fields.choose(&format!("can_{op}_{table}_"), Some(column), "")
                    });
                }
            }
        }
    }

    fn named(
        &self,
        table: &str,
        kind: &'static str,
        detail: &str,
        fallback: impl FnOnce() -> String,
    ) -> String {
        self.get(table, kind, detail).unwrap_or_else(fallback)
    }

    /// `{table}_updated_at_trigger`.
    pub fn updated_at_trigger(&self, table: &str) -> String {
        self.named(table, "updated_at_trigger", "", || {
            make_object_name(table, None, "updated_at_trigger")
        })
    }

    /// `_platform.set_{table}_{slug}`, folded to lower case as Postgres folds the unquoted name.
    pub fn slug_function(&self, table: &str, slug: &str) -> String {
        self.named(table, "slug_function", slug, || {
            make_object_name(
                &format!("set_{}", table.to_ascii_lowercase()),
                Some(&slug.to_ascii_lowercase()),
                "",
            )
        })
    }

    /// `{table}_{slug}_trigger`.
    pub fn slug_trigger(&self, table: &str, slug: &str) -> String {
        self.named(table, "slug_trigger", slug, || {
            make_object_name(table, Some(slug), "trigger")
        })
    }

    /// `_platform.normalise_{table}_rich_text`, folded to lower case.
    pub fn rich_text_function(&self, table: &str) -> String {
        self.named(table, "rich_text_function", "", || {
            make_object_name(
                &format!("normalise_{}", table.to_ascii_lowercase()),
                None,
                "rich_text",
            )
        })
    }

    /// `{table}_rich_text_trigger`.
    pub fn rich_text_trigger(&self, table: &str) -> String {
        self.named(table, "rich_text_trigger", "", || {
            make_object_name(table, None, "rich_text_trigger")
        })
    }

    /// `can_{op}_{table}`, the affordance function taking the table's row type.
    pub fn can_function(&self, table: &str, op: &str) -> String {
        make_object_name(&format!("can_{op}"), Some(table), "")
    }

    /// `can_{op}_{table}__{column}`, a field's affordance function.
    pub fn field_can_function(&self, table: &str, op: &str, column: &str) -> String {
        self.named(table, "field_can", &format!("{op}.{column}"), || {
            make_object_name(&format!("can_{op}_{table}_"), Some(column), "")
        })
    }

    /// The versions layer's `can_edit_{table}`.
    pub fn can_edit_function(&self, table: &str) -> String {
        self.named(table, "can_edit", "", || {
            make_object_name("can_edit", Some(table), "")
        })
    }

    /// The versions layer's `sees_draft_{table}`.
    pub fn sees_draft_function(&self, table: &str) -> String {
        self.named(table, "sees_draft", "", || {
            make_object_name("sees_draft", Some(table), "")
        })
    }

    /// `{versions_table}_guard`, the function and the trigger on the versions table, for `table`.
    pub fn versions_guard(&self, table: &str, versions_table: &str) -> String {
        self.named(table, "versions_guard", "", || {
            make_object_name(versions_table, None, "guard")
        })
    }

    /// `{versions_table}_audit`, the function and the trigger on the model's table, for `table`.
    pub fn versions_audit(&self, table: &str, versions_table: &str) -> String {
        self.named(table, "versions_audit", "", || {
            make_object_name(versions_table, None, "audit")
        })
    }

    /// `api.{table}__write`, the function behind a masked view's write trigger.
    pub fn write_function(&self, table: &str) -> String {
        self.named(table, "write_function", "", || {
            make_object_name(table, None, "_write")
        })
    }

    /// `{table}_write`, the write trigger on a masked view, which is the view's only trigger.
    pub fn write_trigger(&self, table: &str) -> String {
        make_object_name(table, None, "write")
    }

    /// Records the name `choose` picks for this object, unless it has one already: two models
    /// on one table ask for that table's primary key twice, and it is one key.
    fn pick(
        &mut self,
        table: &str,
        kind: &'static str,
        detail: &str,
        choose: impl FnOnce() -> String,
    ) {
        if self.get(table, kind, detail).is_none() {
            let name = choose();
            self.set(table, kind, detail, name);
        }
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
