//! Column type / kind conversion registry: maps (from_udt, to_pg, kinds) to a migration strategy.

use crate::differ::Risk;
use crate::parser::ast::{BlocksFieldAst, DefaultValueAst, FieldAst, ScalarFieldAst};
use crate::sql_quote::{do_block, quote_ident, quote_literal, quote_qualified, raise_message};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionStrategyKind {
    SafeCast,
    TransformCast,
    KindMigrate,
    RecreateColumn,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversionStrategy {
    pub kind: ConversionStrategyKind,
    /// SQL expression for ALTER COLUMN … USING (TransformCast only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub using_expr: Option<String>,
    /// UPDATE … SET before ALTER when PG type unchanged (KindMigrate).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_update: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
}

pub fn is_text_udt(udt: &str) -> bool {
    matches!(udt, "text" | "varchar" | "bpchar")
}

pub fn is_array_udt(udt: &str) -> bool {
    udt.starts_with('_') || udt.ends_with("[]")
}

pub fn is_numeric_udt(udt: &str) -> bool {
    matches!(
        udt,
        "int2" | "int4" | "int8" | "float4" | "float8" | "numeric"
    )
}

pub fn is_scalar_jsonb_source_udt(udt: &str) -> bool {
    matches!(
        udt,
        "int2" | "int4" | "int8" | "float4" | "float8" | "bool" | "numeric"
    )
}

/// Returns true if changing from `from_udt` to `to_pg_type` is a safe widening
/// that Postgres accepts without a USING cast and without data loss.
pub fn is_safe_widening(from_udt: &str, to_pg: &str) -> bool {
    matches!(
        (from_udt, to_pg.to_uppercase().as_str()),
        ("int2", "INTEGER")
            | ("int2", "BIGINT")
            | ("int4", "BIGINT")
            | ("float4", "DOUBLE PRECISION")
            | ("varchar", "TEXT")
            | ("bpchar", "TEXT")
    )
}

/// Extract plain text from a Lexical JSONB document (or jsonb string scalar).
pub fn lexical_plain_text_extract_sql(col: &str) -> String {
    format!(
        "COALESCE((SELECT string_agg(\
            COALESCE(node->>'text', ''), '' ORDER BY ord) \
         FROM jsonb_path_query({col}, '$.root.children[*].children[*]') WITH ORDINALITY AS t(node, ord)), \
         CASE WHEN jsonb_typeof({col}) = 'string' THEN {col} #>> '{{}}' ELSE {col}::text END)",
        col = col
    )
}

/// Wrap plain TEXT as a minimal Lexical SerializedEditorState (single paragraph).
pub fn text_to_lexical_jsonb_expr(column: &str) -> String {
    format!(
        "jsonb_build_object(\
            'root', jsonb_build_object(\
                'type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, \
                'children', jsonb_build_array(\
                    jsonb_build_object(\
                        'type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, \
                        'children', jsonb_build_array(\
                            jsonb_build_object(\
                                'type', 'text', 'version', 1, 'detail', 0, 'format', 0, \
                                'mode', 'normal', 'style', '', 'text', {column}::text\
                            )\
                        )\
                    )\
                )\
            )\
        )",
        column = column
    )
}

/// Convert existing JSONB values to Lexical (json arrays, strings, scalars, etc.).
/// Whether a field stores one value per locale.
///
/// Only rich text is asked about here, but every scalar carries the flag, so this reads it rather
/// than matching on the one variant and quietly returning false for a future one.
pub(crate) fn is_localised(field: &FieldAst) -> bool {
    match field {
        FieldAst::RichText(f) => f.localized,
        _ => false,
    }
}

pub fn jsonb_to_lexical_migrate_expr(col: &str) -> String {
    // Parenthesised, because the caller appends `::text` and a cast binds tighter than the
    // operator: `col #>> '{}'::text` is read as `jsonb #>> text`, which does not exist. The
    // `json -> richText` migration has produced that since it was written, and nothing caught
    // it because nothing tested that conversion.
    let string_text = format!("({col} #>> '{{}}')");
    let array_text = format!(
        "COALESCE((SELECT string_agg(\
            CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{{}}' ELSE elem::text END, \
            E'\\n'\
         ) FROM jsonb_array_elements({col}) AS elem), '')"
    );
    format!(
        "CASE WHEN {col} IS NULL THEN NULL \
         WHEN {col} ? 'root' THEN {col} \
         WHEN jsonb_typeof({col}) = 'string' THEN {lex_string} \
         WHEN jsonb_typeof({col}) = 'array' THEN {lex_array} \
         ELSE {lex_fallback} END",
        col = col,
        lex_string = text_to_lexical_jsonb_expr(&string_text),
        lex_array = text_to_lexical_jsonb_expr(&array_text),
        lex_fallback = text_to_lexical_jsonb_expr(&format!("{col}::text")),
    )
}

/// The same wrap, applied to each locale of a localized column rather than to the column.
///
/// A localized value is `{"en": ..., "fr": ...}`, and it is each locale's value that is the
/// document, not the map holding them. The map has no top-level `root`, is not a string and is
/// not an array, so handing it to {@link jsonb_to_lexical_migrate_expr} falls through to that
/// function's catch-all and stringifies every locale at once into a single text node. The result
/// is a valid Lexical document, which is why nothing downstream complains: the column still type
/// checks, and the content is gone.
///
/// Each locale goes through the ordinary wrap, so a locale already holding a document is left
/// alone by that function's own `? 'root'` guard and this stays safe to re-run.
pub fn jsonb_to_localised_lexical_expr(col: &str) -> String {
    format!(
        "CASE WHEN {col} IS NULL THEN NULL \
         WHEN {col} ? 'root' THEN {col} \
         WHEN jsonb_typeof({col}) <> 'object' THEN {whole} \
         ELSE COALESCE(\
            (SELECT jsonb_object_agg(locale.key, {per_locale}) FROM jsonb_each({col}) AS locale), \
            {col}\
         ) END",
        col = col,
        // A column that is not an object at all is not localized data, whatever the schema says.
        // Wrapping it whole is what the non-localized column would do, and losing it is not.
        whole = jsonb_to_lexical_migrate_expr(col),
        per_locale = jsonb_to_lexical_migrate_expr("locale.value"),
    )
}

/// The normalising expression for a rich text column, localized or not.
///
/// One entry point so the trigger and the `json -> richText` migration cannot disagree about what
/// a rich text column should hold. They ran the same expression before, and shared the same blind
/// spot with it.
pub fn lexical_normalise_expr(col: &str, localised: bool) -> String {
    if localised {
        jsonb_to_localised_lexical_expr(col)
    } else {
        jsonb_to_lexical_migrate_expr(col)
    }
}

fn storage_ref_from_text_expr(col: &str, bucket: &str) -> String {
    format!(
        "CASE WHEN {col} IS NULL THEN NULL \
         WHEN left(trim({col}::text), 1) = '{{' THEN {col}::text::jsonb \
         WHEN {col}::text LIKE '/assets/images/%' THEN \
           jsonb_build_object('bucket', {bucket}, 'path', 'images/' || substring({col}::text from 16)) \
         WHEN {col}::text LIKE '/%' THEN \
           jsonb_build_object('bucket', {bucket}, 'path', ltrim({col}::text, '/')) \
         ELSE jsonb_build_object('bucket', {bucket}, 'path', {col}::text) END",
        col = col,
        bucket = quote_literal(bucket),
    )
}

/// One stored value as a block entry: kept when it already is one (a string `type` beside an object
/// `data`), else the whole object becomes the `data` of a `block_name` entry.
fn block_entry_expr(value: &str, block_name: &str) -> String {
    format!(
        "CASE WHEN jsonb_typeof({value}->'type') = 'string' \
           AND jsonb_typeof({value}->'data') = 'object' THEN {value} \
         ELSE jsonb_build_object('type', {name}, 'data', {value}) END",
        name = quote_literal(block_name),
    )
}

/// JSON to blocks: an object is one entry, an array is one entry per element in order, and `[]`
/// stays `[]`. SQL NULL and JSON `null` are left as they are.
///
/// A value that is not an object, at the top or as an element, is refused before anything is
/// written ([`blocks_refusal_sql`]): a block keeps its fields in an object under `data`, so a
/// string or a number has no field to go in. Wrapping it as `{ "value": ... }` kept it in the row,
/// but under a key no block declares, so Studio showed an empty block and the value could no
/// longer be seen or edited anywhere.
fn json_to_blocks_sql(target: &str, col: &str, table: &str, column: &str, block: &str) -> String {
    let each = block_entry_expr("e.elem", block);
    let one = block_entry_expr(col, block);
    format!(
        "{refusal}\nUPDATE {target} SET {col} = CASE \
           WHEN jsonb_typeof({col}) = 'object' THEN jsonb_build_array({one}) \
           ELSE (SELECT COALESCE(jsonb_agg({each} ORDER BY e.ord), '[]'::jsonb) \
                 FROM jsonb_array_elements({col}) WITH ORDINALITY AS e(elem, ord)) END \
         WHERE jsonb_typeof({col}) IN ('object', 'array');",
        refusal = blocks_refusal_sql(target, col, table, column),
    )
}

/// Raises, naming the column, when any row holds a value [`json_to_blocks_sql`] cannot convert.
fn blocks_refusal_sql(target: &str, col: &str, table: &str, column: &str) -> String {
    let refused = raise_message(&format!(
        "Cannot convert {table}.{column} to blocks: a value is not an object. Each block keeps its \
         fields in an object, so every value must be an object or an array of objects. Change or \
         remove the values that are not, then push again."
    ));
    let body = format!(
        " BEGIN\n  \
         IF EXISTS (SELECT 1 FROM {target} t \
           WHERE jsonb_typeof(t.{col}) NOT IN ('object', 'array', 'null') \
              OR (jsonb_typeof(t.{col}) = 'array' AND EXISTS (\
                SELECT 1 FROM jsonb_array_elements(t.{col}) e WHERE jsonb_typeof(e) <> 'object'))) THEN\n    \
         RAISE EXCEPTION {refused};\n  \
         END IF;\n\
         END "
    );
    do_block("", &body)
}

fn first_block_name(field: &FieldAst) -> Option<String> {
    match field {
        FieldAst::Blocks(BlocksFieldAst { blocks, .. }) => blocks.first().map(|b| b.name.clone()),
        _ => None,
    }
}

fn default_storage_bucket(field: &FieldAst) -> String {
    match field {
        FieldAst::Image(f) | FieldAst::File(f) => f.bucket.clone(),
        _ => "marketing".into(),
    }
}

fn is_geo_udt(udt: &str) -> bool {
    matches!(udt, "geography" | "geometry")
}

fn is_vector_udt(udt: &str) -> bool {
    udt == "vector"
}

fn is_bytea_udt(udt: &str) -> bool {
    udt == "bytea"
}

fn to_pg_upper(pg: &str) -> String {
    pg.to_uppercase()
}

/// Whether a cross-family cast should drop/recreate instead of ALTER USING.
pub fn should_recreate_column(
    from_udt: &str,
    to_pg: &str,
    from_kind: Option<&str>,
    to_kind: Option<&str>,
) -> bool {
    let to = to_pg_upper(to_pg);
    if is_geo_udt(from_udt) || is_vector_udt(from_udt) || is_bytea_udt(from_udt) {
        return true;
    }
    if to.contains("GEOGRAPHY") || to.contains("GEOMETRY") || to.starts_with("VECTOR") {
        return true;
    }
    if from_udt == "jsonb"
        && matches!(
            to.as_str(),
            "INTEGER"
                | "BIGINT"
                | "SMALLINT"
                | "BOOLEAN"
                | "UUID"
                | "DATE"
                | "TIMESTAMPTZ"
                | "TIMESTAMP"
                | "DOUBLE PRECISION"
                | "REAL"
                | "INET"
        )
    {
        return true;
    }
    if is_bytea_udt(from_udt) || to == "BYTEA" {
        return from_udt != "bytea" || to != "BYTEA";
    }
    if from_kind == Some("richText") && to_kind == Some("blocks") {
        return false; // blocked separately
    }
    false
}

pub fn supports_kind_data_migration(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("json", "richText")
            | ("text", "richText")
            | ("integer", "richText")
            | ("float", "richText")
            | ("boolean", "richText")
            | ("bigInt", "richText")
            | ("smallInt", "richText")
            | ("json", "blocks")
            | ("blocks", "json")
            | ("richText", "json")
            | ("blocks", "richText")
    )
}

pub fn kind_migrate_pre_update(
    table: &str,
    column: &str,
    schema: &str,
    from: &str,
    to: &str,
    target_field: &FieldAst,
) -> Option<String> {
    let col = quote_ident(column);
    let target = quote_qualified(schema, table);
    match (from, to) {
        ("json", "richText") => Some(format!(
            "UPDATE {target} SET {col} = {expr} \
             WHERE {col} IS NOT NULL AND NOT ({col} ? 'root');",
            expr = lexical_normalise_expr(&col, is_localised(target_field)),
        )),
        ("json", "blocks") => {
            let block = first_block_name(target_field).unwrap_or_else(|| "block".into());
            Some(json_to_blocks_sql(&target, &col, table, column, &block))
        }
        ("blocks", "richText") => {
            let array_text = format!(
                "COALESCE((SELECT string_agg(COALESCE(elem->'data'->>'value', elem->'data'::text, ''), E'\\n') \
                 FROM jsonb_array_elements({col}) elem), '')"
            );
            Some(format!(
                "UPDATE {target} SET {col} = {lex} \
                 WHERE {col} IS NOT NULL AND jsonb_typeof({col}) = 'array';",
                lex = text_to_lexical_jsonb_expr(&array_text),
            ))
        }
        ("richText", "json") => None, // already valid JSONB
        ("blocks", "json") => None,
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn plan_type_conversion(
    table: &str,
    column: &str,
    schema: &str,
    from_udt: &str,
    to_pg: &str,
    from_kind: Option<&str>,
    to_kind: Option<&str>,
    changes: &serde_json::Value,
    target_field: &FieldAst,
) -> ConversionStrategy {
    if let Some(loc) = changes.get("localization") {
        let direction = loc
            .get("direction")
            .and_then(|v| v.as_str())
            .unwrap_or("add");
        // Only unwrap locale maps, never Lexical richText / json / blocks documents.
        if direction == "remove"
            && matches!(from_kind, Some("richText") | Some("json") | Some("blocks"))
        {
            // fall through to jsonb → TEXT richText extraction below
        } else {
            let locale = loc
                .get("default_locale")
                .and_then(|v| v.as_str())
                .unwrap_or("en");
            let (locale, col) = (quote_literal(locale), quote_ident(column));
            let using = if direction == "add" {
                format!("jsonb_build_object({locale}, {col}::text)")
            } else {
                format!("({col}->>{locale})::text")
            };
            return ConversionStrategy {
                kind: ConversionStrategyKind::TransformCast,
                using_expr: Some(using),
                pre_update: None,
                blocked_reason: None,
            };
        }
    }

    if from_kind == Some("richText") && to_kind == Some("blocks") {
        return ConversionStrategy {
            kind: ConversionStrategyKind::Blocked,
            using_expr: None,
            pre_update: None,
            blocked_reason: Some(
                "richText → blocks requires manual restructuring; change field in schema or use a new column"
                    .into(),
            ),
        };
    }

    if is_safe_widening(from_udt, to_pg) {
        return ConversionStrategy {
            kind: ConversionStrategyKind::SafeCast,
            using_expr: None,
            pre_update: None,
            blocked_reason: None,
        };
    }

    if should_recreate_column(from_udt, to_pg, from_kind, to_kind) {
        return ConversionStrategy {
            kind: ConversionStrategyKind::RecreateColumn,
            using_expr: None,
            pre_update: None,
            blocked_reason: None,
        };
    }

    let to_upper = to_pg_upper(to_pg);
    let col = quote_ident(column);

    if to_upper == "JSONB" {
        if to_kind == Some("richText") {
            let using = if is_text_udt(from_udt) {
                format!(
                    "CASE WHEN {col} IS NULL THEN NULL \
                     WHEN left(trim({col}::text), 1) = '{{' AND ({col}::text::jsonb ? 'root') THEN {col}::text::jsonb \
                     ELSE {lex} END",
                    col = col,
                    lex = text_to_lexical_jsonb_expr(&col),
                )
            } else {
                format!(
                    "CASE WHEN {col} IS NULL THEN NULL ELSE {lex} END",
                    col = col,
                    lex = text_to_lexical_jsonb_expr(&format!("{col}::text")),
                )
            };
            return ConversionStrategy {
                kind: ConversionStrategyKind::TransformCast,
                using_expr: Some(using),
                pre_update: None,
                blocked_reason: None,
            };
        }

        if matches!(to_kind, Some("image") | Some("file")) && is_text_udt(from_udt) {
            let bucket = default_storage_bucket(target_field);
            return ConversionStrategy {
                kind: ConversionStrategyKind::TransformCast,
                using_expr: Some(storage_ref_from_text_expr(&col, &bucket)),
                pre_update: None,
                blocked_reason: None,
            };
        }

        if is_text_udt(from_udt) {
            let using = match to_kind {
                Some("json") | Some("blocks") => format!(
                    "CASE WHEN {col} IS NULL THEN NULL \
                     WHEN left(trim({col}::text), 1) IN ('{{', '[') THEN {col}::text::jsonb \
                     ELSE to_jsonb({col}::text) END",
                    col = col,
                ),
                _ => format!("to_jsonb({col}::text)", col = col),
            };
            return ConversionStrategy {
                kind: ConversionStrategyKind::TransformCast,
                using_expr: Some(using),
                pre_update: None,
                blocked_reason: None,
            };
        }

        if is_scalar_jsonb_source_udt(from_udt) || from_udt == "bool" {
            return ConversionStrategy {
                kind: ConversionStrategyKind::TransformCast,
                using_expr: Some(format!("to_jsonb({col})", col = col)),
                pre_update: None,
                blocked_reason: None,
            };
        }

        if is_array_udt(from_udt) {
            return ConversionStrategy {
                kind: ConversionStrategyKind::TransformCast,
                using_expr: Some(format!("to_jsonb({col})", col = col)),
                pre_update: None,
                blocked_reason: None,
            };
        }
    }

    if to_upper == "TEXT" && from_udt == "jsonb" {
        let using = if changes.get("localization").is_some() {
            format!("({col}->>'en')::text")
        } else if from_kind == Some("richText") {
            // Postgres forbids subqueries in ALTER COLUMN … USING, so extract in an UPDATE first.
            let extract = lexical_plain_text_extract_sql(&col);
            return ConversionStrategy {
                kind: ConversionStrategyKind::TransformCast,
                using_expr: Some(format!("({col} #>> '{{}}')::text")),
                pre_update: Some(format!(
                    "UPDATE {} SET {col} = to_jsonb({extract}) WHERE {col} IS NOT NULL;",
                    quote_qualified(schema, table)
                )),
                blocked_reason: None,
            };
        } else {
            format!("{col}::text", col = col)
        };
        return ConversionStrategy {
            kind: ConversionStrategyKind::TransformCast,
            using_expr: Some(using),
            pre_update: None,
            blocked_reason: None,
        };
    }

    if is_text_udt(from_udt)
        && matches!(
            to_upper.as_str(),
            "INTEGER" | "BIGINT" | "SMALLINT" | "DOUBLE PRECISION" | "REAL" | "BOOLEAN" | "UUID"
        )
    {
        return ConversionStrategy {
            kind: ConversionStrategyKind::TransformCast,
            using_expr: Some(format!(
                "NULLIF(trim({col}::text), '')::{to_pg}",
                col = col,
                to_pg = to_pg
            )),
            pre_update: None,
            blocked_reason: None,
        };
    }

    if from_udt == "uuid" && to_upper == "TEXT" {
        return ConversionStrategy {
            kind: ConversionStrategyKind::TransformCast,
            using_expr: Some(format!("{col}::text", col = col)),
            pre_update: None,
            blocked_reason: None,
        };
    }

    if from_udt == "text" && to_upper == "UUID" {
        return ConversionStrategy {
            kind: ConversionStrategyKind::TransformCast,
            using_expr: Some(format!("{col}::uuid", col = col)),
            pre_update: None,
            blocked_reason: None,
        };
    }

    if from_udt == "jsonb" && !to_upper.starts_with("JSONB") {
        return ConversionStrategy {
            kind: ConversionStrategyKind::RecreateColumn,
            using_expr: None,
            pre_update: None,
            blocked_reason: None,
        };
    }

    ConversionStrategy {
        kind: ConversionStrategyKind::TransformCast,
        using_expr: Some(format!("{col}::{to_pg}")),
        pre_update: None,
        blocked_reason: None,
    }
}

pub fn strategy_risk(strategy: &ConversionStrategy, changes: &serde_json::Value) -> Risk {
    if let Some(loc) = changes.get("localization") {
        if loc.get("direction").and_then(|v| v.as_str()) == Some("remove") {
            return Risk::Destructive;
        }
    }
    match strategy.kind {
        ConversionStrategyKind::SafeCast => Risk::Safe,
        ConversionStrategyKind::TransformCast | ConversionStrategyKind::KindMigrate => {
            Risk::Cautious
        }
        ConversionStrategyKind::RecreateColumn => Risk::Destructive,
        ConversionStrategyKind::Blocked => Risk::Destructive,
    }
}

fn required_scalar_no_default(f: &ScalarFieldAst) -> bool {
    f.required && !f.primary_key && f.default.is_none()
}

fn is_lexical_document_value(value: &serde_json::Value) -> bool {
    value.as_object().and_then(|o| o.get("root")).is_some()
}

/// True when `s` is JSON text for a Lexical `SerializedEditorState` (has top-level `root`).
fn is_lexical_json_string(s: &str) -> bool {
    let trimmed = s.trim();
    if !trimmed.starts_with('{') {
        return false;
    }
    serde_json::from_str::<serde_json::Value>(trimmed)
        .ok()
        .as_ref()
        .is_some_and(is_lexical_document_value)
}

/// SQL DEFAULT expression for a RichText field: plain string → Lexical paragraph; Lexical JSON → `jsonb`.
pub fn rich_text_default_sql(default: &DefaultValueAst) -> Option<String> {
    match default {
        DefaultValueAst::Value {
            value: serde_json::Value::String(s),
        } => {
            if is_lexical_json_string(s) {
                Some(format!("{}::jsonb", quote_literal(s)))
            } else {
                Some(text_to_lexical_jsonb_expr(&quote_literal(s)))
            }
        }
        DefaultValueAst::Value { value } if is_lexical_document_value(value) => {
            let json = serde_json::to_string(value).ok()?;
            Some(format!("{}::jsonb", quote_literal(&json)))
        }
        _ => None,
    }
}

/// Short diff warning when a required field is added to an existing table without auto-backfill.
pub fn required_field_existing_table_warning(table: &str, column: &str) -> String {
    format!(
        "Adding required field \"{column}\" to existing table \"{table}\". \
         If rows already exist and this type has no automatic backfill, push may fail. \
         Use Optional<…>, Default<…> / an inline default, update seed, or reset local data."
    )
}

/// DEFAULT expression for ADD COLUMN on a table that already has rows (required, no schema default).
///
/// None for a column the database fills itself: an identity column numbers the existing rows from
/// its sequence and a generated one computes them, and Postgres refuses a `DEFAULT` beside either
/// (`both default and identity specified`).
pub fn add_column_backfill_default(field: &FieldAst) -> Option<String> {
    if crate::parser::accessors::database_fills(field) {
        return None;
    }
    match field {
        FieldAst::RichText(f) if required_scalar_no_default(f) => {
            Some(text_to_lexical_jsonb_expr("''"))
        }
        FieldAst::Text(f)
        | FieldAst::Color(f)
        | FieldAst::Email(f)
        | FieldAst::Url(f)
        | FieldAst::Xml(f)
        | FieldAst::Bytes(f)
            if required_scalar_no_default(f) =>
        {
            Some("''".into())
        }
        FieldAst::Slug(f) if f.required => Some("''".into()),
        FieldAst::Boolean(f) if required_scalar_no_default(f) => Some("false".into()),
        FieldAst::Integer(f) | FieldAst::SmallInt(f) | FieldAst::BigInt(f)
            if required_scalar_no_default(f) =>
        {
            Some("0".into())
        }
        FieldAst::Float(f) if required_scalar_no_default(f) => Some("0".into()),
        FieldAst::Decimal(f) if f.required => Some("0".into()),
        FieldAst::Money(f) if f.required => Some("0".into()),
        FieldAst::Json(f) if f.required => Some("'{}'::jsonb".into()),
        FieldAst::Blocks(f) if f.required => Some("'[]'::jsonb".into()),
        FieldAst::Enum(f) if f.required && f.default.is_none() => {
            f.values.first().map(|v| quote_literal(v))
        }
        _ => None,
    }
}

pub fn using_expr_for_alter(strategy: &ConversionStrategy, column: &str, to_pg: &str) -> String {
    let cast = || format!("{}::{to_pg}", quote_ident(column));
    match &strategy.kind {
        ConversionStrategyKind::SafeCast | ConversionStrategyKind::TransformCast => {
            strategy.using_expr.clone().unwrap_or_else(cast)
        }
        ConversionStrategyKind::KindMigrate
        | ConversionStrategyKind::RecreateColumn
        | ConversionStrategyKind::Blocked => cast(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ast::{GeneratedColumnAst, IdentityGeneration, ScalarFieldAst};

    fn rich_text(localized: bool) -> FieldAst {
        let mut scalar = ScalarFieldAst {
            pg_type: "JSONB".into(),
            required: false,
            unique: false,
            ..Default::default()
        };
        scalar.localized = localized;
        FieldAst::RichText(scalar)
    }

    /// A localized column is wrapped per locale, and a plain one is not.
    ///
    /// Asserted on `jsonb_each`, because that is the whole difference: without it the locale map
    /// is handed to the wrap as a single value and comes back as one text node holding every
    /// locale as literal JSON.
    #[test]
    fn a_localised_rich_text_column_is_normalised_one_locale_at_a_time() {
        let localised = lexical_normalise_expr("\"bio\"", true);
        assert!(
            localised.contains("jsonb_each"),
            "per locale, not whole: {localised}"
        );
        assert!(
            !lexical_normalise_expr("\"bio\"", false).contains("jsonb_each"),
            "a plain column keeps the single-value wrap"
        );
    }

    /// The migration reads the flag off the field, so it and the trigger cannot disagree.
    #[test]
    fn the_json_to_rich_text_migration_follows_the_field() {
        let localised = kind_migrate_pre_update(
            "article",
            "summary",
            "public",
            "json",
            "richText",
            &rich_text(true),
        )
        .expect("the conversion is supported");
        assert!(
            localised.contains("jsonb_each"),
            "localized target: {localised}"
        );

        let plain = kind_migrate_pre_update(
            "article",
            "body",
            "public",
            "json",
            "richText",
            &rich_text(false),
        )
        .expect("the conversion is supported");
        assert!(!plain.contains("jsonb_each"), "plain target: {plain}");
    }

    fn required_int(
        identity: Option<IdentityGeneration>,
        auto_increment: bool,
        generated: Option<&str>,
    ) -> FieldAst {
        FieldAst::Integer(ScalarFieldAst {
            pg_type: "INTEGER".into(),
            required: true,
            identity,
            auto_increment,
            generated: generated.map(|expression| GeneratedColumnAst {
                expression: expression.into(),
                stored: true,
            }),
            ..Default::default()
        })
    }

    /// A required column the database fills gets no backfill `DEFAULT`, which Postgres refuses
    /// beside an identity or a generation expression; a plain one still gets its zero.
    #[test]
    fn a_column_the_database_fills_has_no_backfill_default() {
        assert_eq!(
            add_column_backfill_default(&required_int(None, false, None)).as_deref(),
            Some("0")
        );
        for field in [
            required_int(Some(IdentityGeneration::Always), false, None),
            required_int(Some(IdentityGeneration::ByDefault), false, None),
            required_int(Some(IdentityGeneration::ByDefault), true, None),
            required_int(None, false, Some("1 + 1")),
        ] {
            assert_eq!(add_column_backfill_default(&field), None, "{field:?}");
        }
    }

    #[test]
    fn only_rich_text_can_be_localised_here() {
        assert!(is_localised(&rich_text(true)));
        assert!(!is_localised(&rich_text(false)));
    }
}
