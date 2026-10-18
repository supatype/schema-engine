//! Moving block entries stored in the flat shape to the shape 0.7.0 reads.
//!
//! Before 0.7.0 a block entry held its fields beside its name, `{ type, meta?, ...fields }`. Since
//! then it holds them under `data`, `{ type, data: fields, meta? }`, and the fields under `data`
//! have the shape a model's column gives them: a `Localized` field is a locale map and a
//! `RichText` field is Lexical editor state. Studio reads a block's fields from `data` only, so an
//! entry left flat opens with every field empty, and saving it there loses its text.
//!
//! This module writes the SQL a push uses to find and move such entries, for each `Blocks` column
//! of the schema and the copy of it every snapshot of a versioned model holds. Everything is plain
//! SQL expressions, no helper functions, so the statements recorded in the migration are the whole
//! of what ran.
//!
//! An entry is moved only when it is an object, has no `data` key and names a block the column
//! declares. Anything else is left exactly as it is: an entry that already has `data` (so a second
//! push changes nothing), a value that is not an object, and a block type the schema no longer
//! declares, which the push reports rather than guess at.

use crate::parser::accessors::{is_localized, versions_of, versions_table_name};
use crate::parser::ast::{BlockDefinitionAst, FieldAst, ModelAst, SchemaAst};
use crate::sql_quote::{quote_ident, quote_literal, quote_qualified};

/// How one field of a block is moved under `data`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldShape {
    /// Kept as it is.
    Plain,
    /// One value becomes a map holding it under the default locale.
    Localized,
    /// A plain string becomes one paragraph of Lexical state.
    RichText,
    /// Both: each locale's value is Lexical state.
    LocalizedRichText,
}

impl FieldShape {
    /// The shape of `field` inside a block. A nested `Blocks` field is kept as it is: the CLI
    /// sends no block definitions for one, so there is nothing to move it by.
    pub fn of(field: &FieldAst) -> FieldShape {
        match field {
            FieldAst::RichText(f) if f.localized => FieldShape::LocalizedRichText,
            FieldAst::RichText(_) => FieldShape::RichText,
            FieldAst::Blocks(_) => FieldShape::Plain,
            other if is_localized(other) => FieldShape::Localized,
            _ => FieldShape::Plain,
        }
    }
}

/// One block a column declares, with the fields that change shape when it moves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockShape {
    pub name: String,
    /// Only the fields that are not [`FieldShape::Plain`], in declaration order.
    pub fields: Vec<(String, FieldShape)>,
}

impl BlockShape {
    fn of(block: &BlockDefinitionAst) -> BlockShape {
        let fields = block
            .fields
            .iter()
            .map(|(name, field)| (name.clone(), FieldShape::of(field)))
            .filter(|(_, shape)| *shape != FieldShape::Plain)
            .collect();
        BlockShape {
            name: block.name.clone(),
            fields,
        }
    }
}

/// The locales a localized value may be keyed by, and the one a single value goes under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locales {
    pub default: String,
    pub all: Vec<String>,
}

impl Locales {
    pub fn of(ast: &SchemaAst) -> Locales {
        let default = ast.effective_default_locale().to_string();
        let mut all = ast.locales.clone();
        if !all.contains(&default) {
            all.push(default.clone());
        }
        Locales { default, all }
    }
}

/// A `Blocks` column the schema declares, and the snapshot table that copies it when the model
/// keeps versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockColumn {
    pub table: String,
    pub column: String,
    /// `Localized<Blocks>`: the column holds one array per locale.
    pub localized: bool,
    pub blocks: Vec<BlockShape>,
    pub versions_table: Option<String>,
    pub locales: Locales,
}

impl BlockColumn {
    /// `table.column`, as the push names the column to a person.
    pub fn label(&self) -> String {
        format!("{}.{}", self.table, self.column)
    }
}

/// Every `Blocks` column of `ast` that declares at least one block, in model and field order.
pub fn block_columns(ast: &SchemaAst) -> Vec<BlockColumn> {
    let locales = Locales::of(ast);
    ast.models
        .iter()
        .flat_map(|model| model_block_columns(model, &locales))
        .collect()
}

fn model_block_columns(model: &ModelAst, locales: &Locales) -> Vec<BlockColumn> {
    let table = model.table_name().to_string();
    let versions_table = versions_of(model).map(|_| versions_table_name(&table));
    model
        .fields
        .iter()
        .filter_map(|(name, field)| match field {
            FieldAst::Blocks(f) if !f.blocks.is_empty() => Some(BlockColumn {
                table: table.clone(),
                column: name.clone(),
                localized: f.localized,
                blocks: f.blocks.iter().map(BlockShape::of).collect(),
                versions_table: versions_table.clone(),
                locales: locales.clone(),
            }),
            _ => None,
        })
        .collect()
}

/// Where a column's value is read from: the live table's column, or its copy in a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Site {
    Live,
    Versions,
}

impl BlockColumn {
    fn relation(&self, schema: &str, site: Site) -> Option<String> {
        match site {
            Site::Live => Some(quote_qualified(schema, &self.table)),
            Site::Versions => self
                .versions_table
                .as_ref()
                .map(|v| quote_qualified(schema, v)),
        }
    }

    /// The value as an expression over the row alias `t`.
    fn value(&self, site: Site) -> String {
        match site {
            Site::Live => format!("t.{}", quote_ident(&self.column)),
            Site::Versions => format!("(t.\"data\" -> {})", quote_literal(&self.column)),
        }
    }

    fn known_types(&self) -> String {
        let names: Vec<String> = self.blocks.iter().map(|b| quote_literal(&b.name)).collect();
        names.join(", ")
    }

    /// True for an entry `e` this push moves: an object with no `data` naming a declared block.
    fn is_flat(&self, e: &str) -> String {
        format!(
            "(jsonb_typeof({e}) = 'object' AND NOT {e} ? 'data' \
             AND jsonb_typeof({e} -> 'type') = 'string' AND ({e} ->> 'type') IN ({known}))",
            known = self.known_types(),
        )
    }

    /// True for an entry `e` left alone because nothing says how to move it: a value that is not
    /// an object, or an object without `data` that names no declared block.
    fn is_unknown(&self, e: &str) -> String {
        format!(
            "(jsonb_typeof({e}) <> 'object' OR (NOT {e} ? 'data' AND NOT {flat}))",
            flat = self.is_flat(e),
        )
    }
}

/// True for an entry `e` that has `data` and fields beside it too: one opened in Studio while
/// still flat and saved there, whose old text no renderer reads. Left alone, since which copy of
/// a field is right is a person's call.
fn is_mixed(e: &str) -> String {
    format!(
        "(jsonb_typeof({e}) = 'object' AND {e} ? 'data' \
         AND ({e} - 'type' - 'data' - 'meta') <> '{{}}'::jsonb)"
    )
}

/// One paragraph of Lexical state holding the text of the JSON string `v`, as Studio's editor
/// saves it and `examples/kitchen-sink/seed.ts` writes it.
fn paragraph(v: &str) -> String {
    format!(
        "jsonb_build_object('root', jsonb_build_object(\
         'type', 'root', 'version', 1, 'direction', NULL, 'format', '', 'indent', 0, \
         'children', jsonb_build_array(jsonb_build_object(\
         'type', 'paragraph', 'version', 1, 'direction', NULL, 'format', '', 'indent', 0, \
         'children', jsonb_build_array(jsonb_build_object(\
         'type', 'text', 'version', 1, 'text', {v} #>> '{{}}', 'format', 0, 'detail', 0, \
         'mode', 'normal', 'style', ''))))))"
    )
}

/// `RichText`: a plain string becomes one paragraph. Editor state, `null` and anything else is
/// kept as it is.
fn rich_text(v: &str) -> String {
    format!(
        "CASE WHEN jsonb_typeof({v}) = 'string' THEN {p} ELSE {v} END",
        p = paragraph(v)
    )
}

/// `Localized`: a value that is not already a locale map goes under the default locale. A locale
/// map is an object keyed only by the schema's locales; `null` is kept.
fn localized(v: &str, locales: &Locales) -> String {
    let all: Vec<String> = locales.all.iter().map(|l| quote_literal(l)).collect();
    format!(
        "CASE WHEN {v} IS NULL OR jsonb_typeof({v}) = 'null' THEN {v} \
         WHEN jsonb_typeof({v}) = 'object' AND NOT EXISTS (SELECT 1 FROM jsonb_object_keys({v}) \
         AS lk(k) WHERE lk.k <> ALL (ARRAY[{all}]::text[])) THEN {v} \
         ELSE jsonb_build_object({default}, {v}) END",
        all = all.join(", "),
        default = quote_literal(&locales.default),
    )
}

/// `Localized<RichText>`: a string or editor state goes under the default locale as editor
/// state, and each value of a locale map becomes editor state.
fn localized_rich_text(v: &str, locales: &Locales) -> String {
    format!(
        "CASE WHEN jsonb_typeof({v}) = 'string' OR (jsonb_typeof({v}) = 'object' AND {v} ? 'root') \
         THEN jsonb_build_object({default}, {whole}) \
         WHEN jsonb_typeof({v}) = 'object' THEN COALESCE((SELECT jsonb_object_agg(lv.key, {each}) \
         FROM jsonb_each({v}) AS lv), {v}) \
         ELSE {v} END",
        default = quote_literal(&locales.default),
        whole = rich_text(v),
        each = rich_text("lv.value"),
    )
}

fn moved_field(v: &str, shape: FieldShape, locales: &Locales) -> String {
    match shape {
        FieldShape::Plain => v.to_string(),
        FieldShape::Localized => localized(v, locales),
        FieldShape::RichText => rich_text(v),
        FieldShape::LocalizedRichText => localized_rich_text(v, locales),
    }
}

/// The `data` of a flat entry `e` of `block`: every field but `type` and `meta`, each that changes
/// shape replaced by its moved value.
fn block_data(e: &str, block: &BlockShape, locales: &Locales) -> String {
    let mut data = format!("({e} - 'type' - 'meta')");
    for (name, shape) in &block.fields {
        let field = quote_literal(name);
        let value = format!("({e} -> {field})");
        data.push_str(&format!(
            " || CASE WHEN {e} ? {field} THEN jsonb_build_object({field}, {moved}) \
             ELSE '{{}}'::jsonb END",
            moved = moved_field(&value, *shape, locales),
        ));
    }
    data
}

impl BlockColumn {
    /// A flat entry `e` as `{ type, data, meta? }`.
    fn moved_entry(&self, e: &str) -> String {
        let arms: String = self
            .blocks
            .iter()
            .map(|b| {
                format!(
                    " WHEN {name} THEN {data}",
                    name = quote_literal(&b.name),
                    data = block_data(e, b, &self.locales)
                )
            })
            .collect();
        format!(
            "(jsonb_build_object('type', {e} -> 'type', 'data', CASE {e} ->> 'type'{arms} END) \
             || CASE WHEN {e} ? 'meta' THEN jsonb_build_object('meta', {e} -> 'meta') \
             ELSE '{{}}'::jsonb END)"
        )
    }

    /// The array `a` with each flat entry moved, in order. Anything but an array is kept.
    fn moved_array(&self, a: &str) -> String {
        format!(
            "CASE WHEN jsonb_typeof({a}) = 'array' THEN (SELECT COALESCE(jsonb_agg(\
             CASE WHEN {flat} THEN {moved} ELSE blk.e END ORDER BY blk.n), '[]'::jsonb) \
             FROM jsonb_array_elements({a}) WITH ORDINALITY AS blk(e, n)) ELSE {a} END",
            flat = self.is_flat("blk.e"),
            moved = self.moved_entry("blk.e"),
        )
    }

    /// The column's value `c` moved: its array, or on a `Localized<Blocks>` each locale's array.
    fn moved_value(&self, c: &str) -> String {
        if !self.localized {
            return self.moved_array(c);
        }
        format!(
            "CASE WHEN jsonb_typeof({c}) = 'object' THEN COALESCE((SELECT jsonb_object_agg(\
             loc.key, {each}) FROM jsonb_each({c}) AS loc), {c}) ELSE {c} END",
            each = self.moved_array("loc.value"),
        )
    }

    /// The entries of the value `c`, one row each as `blk.e`: what is counted and searched.
    fn entries(&self, c: &str) -> String {
        let array = |a: &str| {
            format!(
                "jsonb_array_elements(CASE WHEN jsonb_typeof({a}) = 'array' THEN {a} \
                 ELSE '[]'::jsonb END) AS blk(e)"
            )
        };
        if !self.localized {
            return array(c);
        }
        format!(
            "jsonb_each(CASE WHEN jsonb_typeof({c}) = 'object' THEN {c} ELSE '{{}}'::jsonb END) \
             AS loc CROSS JOIN LATERAL {each}",
            each = array("loc.value"),
        )
    }

    fn has_flat(&self, c: &str) -> String {
        format!(
            "EXISTS (SELECT 1 FROM {entries} WHERE {flat})",
            entries = self.entries(c),
            flat = self.is_flat("blk.e"),
        )
    }
}

impl BlockColumn {
    /// One query counting, for the live table and its snapshot table, the flat entries a push
    /// moves, the rows holding them, the entries it leaves alone and those with `data` and fields
    /// beside it. One pass over each table, reading only.
    pub fn count_sql(&self, schema: &str, sites: &[Site]) -> String {
        let parts: Vec<String> = sites
            .iter()
            .filter_map(|site| self.count_site(schema, *site))
            .collect();
        parts.join("\nUNION ALL\n")
    }

    fn count_site(&self, schema: &str, site: Site) -> Option<String> {
        let relation = self.relation(schema, site)?;
        let label = match site {
            Site::Live => "live",
            Site::Versions => "versions",
        };
        Some(format!(
            "SELECT {label} AS site, COALESCE(sum(s.flat), 0)::bigint AS entries, \
             count(*) FILTER (WHERE s.flat > 0) AS with_flat, \
             COALESCE(sum(s.unknown), 0)::bigint AS left_alone, \
             COALESCE(sum(s.mixed), 0)::bigint AS mixed \
             FROM ONLY {relation} AS t CROSS JOIN LATERAL (SELECT \
             count(*) FILTER (WHERE {flat}) AS flat, count(*) FILTER (WHERE {unknown}) AS unknown, \
             count(*) FILTER (WHERE {mixed}) AS mixed FROM {entries}) AS s",
            label = quote_literal(label),
            flat = self.is_flat("blk.e"),
            unknown = self.is_unknown("blk.e"),
            mixed = is_mixed("blk.e"),
            entries = self.entries(&self.value(site)),
        ))
    }

    /// The statements that move the flat entries at `site`. On the snapshot table the guard
    /// trigger restores `data` on every `UPDATE`, so the statement runs with the session's
    /// triggers off (`session_replication_role = replica`) and they are back on before the next
    /// statement. That takes no lock beyond the rows written and leaves alone any trigger someone
    /// turned off themselves, which `ALTER TABLE ... ENABLE TRIGGER USER` would turn back on.
    pub fn move_sql(&self, schema: &str, site: Site) -> Vec<String> {
        let Some(relation) = self.relation(schema, site) else {
            return Vec::new();
        };
        let value = self.value(site);
        match site {
            Site::Live => vec![format!(
                "UPDATE {relation} AS t SET {col} = {moved} WHERE {has};",
                col = quote_ident(&self.column),
                moved = self.moved_value(&value),
                has = self.has_flat(&value),
            )],
            Site::Versions => vec![
                "SET LOCAL session_replication_role = replica;".to_string(),
                format!(
                    "UPDATE {relation} AS t SET \"data\" = jsonb_set(t.\"data\", ARRAY[{key}], \
                     {moved}) WHERE t.\"data\" ? {key} AND {has};",
                    key = quote_literal(&self.column),
                    moved = self.moved_value(&value),
                    has = self.has_flat(&value),
                ),
                "SET LOCAL session_replication_role = origin;".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn column(localized: bool) -> BlockColumn {
        BlockColumn {
            table: "page".into(),
            column: "body".into(),
            localized,
            blocks: vec![BlockShape {
                name: "hero".into(),
                fields: vec![("heading".into(), FieldShape::Localized)],
            }],
            versions_table: Some("page_versions".into()),
            locales: Locales {
                default: "en".into(),
                all: vec!["en".into(), "fr".into()],
            },
        }
    }

    #[test]
    fn only_declared_blocks_are_moved() {
        let flat = column(false).is_flat("e");
        assert!(flat.contains("IN ('hero')"), "{flat}");
        assert!(flat.contains("NOT e ? 'data'"), "{flat}");
    }

    #[test]
    fn the_snapshot_update_runs_with_triggers_off_and_turns_them_back_on() {
        let sql = column(false).move_sql("public", Site::Versions);
        assert_eq!(sql.len(), 3);
        assert!(sql[0].contains("replica"));
        assert!(
            sql[1].contains("\"public\".\"page_versions\""),
            "{}",
            sql[1]
        );
        assert!(sql[2].contains("origin"));
    }

    #[test]
    fn a_model_without_versions_has_no_snapshot_statements() {
        let mut col = column(false);
        col.versions_table = None;
        assert!(col.move_sql("public", Site::Versions).is_empty());
        assert!(!col
            .count_sql("public", &[Site::Live, Site::Versions])
            .contains("UNION"));
    }

    #[test]
    fn a_localized_blocks_column_is_moved_per_locale() {
        let sql = column(true).move_sql("public", Site::Live).join("\n");
        assert!(sql.contains("jsonb_each(t.\"body\")"), "{sql}");
    }
}
