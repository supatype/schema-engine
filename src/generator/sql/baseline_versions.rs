//! Version 1 for each record of a drafts model that has no version rows.
//!
//! Studio, `publish` and the history all read a record's publication from its version rows, so a
//! record with none reads as never published even while the public is reading it. Rows get there
//! three ways: a seed, an insert through the API (with or without `published_at`), and anything
//! saved before 0.7.0 wrote versions. This module writes the SQL for both halves of the fix:
//!
//! * **The backfill** a push runs, once, for the records already there: version 1 holding the live
//!   row, live for what the row already shows. Plain SQL, no helper functions, so the statements
//!   recorded in the migration are the whole of what ran.
//! * **The trigger** that gives a row inserted from now on its version 1 as it is inserted, so the
//!   history is complete going forward. `create_record` writes version 1 itself, from what the
//!   caller typed rather than from the row it inserted holding no locale, so the trigger stands
//!   aside for it.
//!
//! What a live row says of its publication is one rule, used by both:
//!
//! * `published_at` at or before now: live, for every locale the row holds content in (or the
//!   whole record, on a model with no localized column). That is what the read rule
//!   `published_at <= now()` shows.
//! * `published_at` in the future: scheduled for those locales at that time, which the scheduler
//!   then publishes, so the state the version rows record catches up with what the rule will show.
//! * `published_at` null: a draft.
//! * No `published_at` column: live now, since nothing in the row withholds it.

use crate::parser::accessors::{db_table_name, versions_of, versions_table_name};
use crate::parser::ast::{ModelAst, SchemaAst};
use crate::sql_quote::{dollar_quote, quote_ident, quote_literal, quote_qualified};

use super::versions::{localized_columns, model_primary_key, HELPER_SCHEMA, PUBLISHED_AT_COLUMN};

/// The setting `create_record` turns on around its insert, so the trigger leaves version 1 to it.
pub const CREATING_RECORD_SETTING: &str = "supatype.creating_record";

/// A drafts model, as its version 1 is written from its live rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineModel {
    pub table: String,
    pub versions_table: String,
    pub primary_key: String,
    /// Columns holding one value per locale. Empty, or no project locales, publishes as `*`.
    localized_columns: Vec<String>,
    locales: Vec<String>,
    has_published_at: bool,
}

/// Every model of `ast` with drafts, in declaration order.
pub fn baseline_models(ast: &SchemaAst) -> Vec<BaselineModel> {
    ast.models
        .iter()
        .filter_map(|m| BaselineModel::of(m, ast))
        .collect()
}

impl BaselineModel {
    /// `model` when it keeps drafts.
    pub fn of(model: &ModelAst, ast: &SchemaAst) -> Option<BaselineModel> {
        if !versions_of(model).is_some_and(|v| v.drafts) {
            return None;
        }
        let table = db_table_name(model).to_string();
        Some(BaselineModel {
            versions_table: versions_table_name(&table),
            primary_key: model_primary_key(model).0,
            localized_columns: localized_columns(model),
            locales: ast.locales.clone(),
            has_published_at: model.fields.contains_key(PUBLISHED_AT_COLUMN),
            table,
        })
    }

    /// When the live row `r` (a `jsonb` expression) goes live.
    fn live_at(&self, r: &str) -> String {
        if self.has_published_at {
            format!(
                "({r} ->> {})::timestamptz",
                quote_literal(PUBLISHED_AT_COLUMN)
            )
        } else {
            "now()".to_string()
        }
    }

    /// The locales live row `r` holds content for, each mapped to `at`: one key `*` on a model
    /// that publishes as a whole, as `_supatype.default_locales` says.
    fn locale_map(&self, r: &str, at: &str) -> String {
        if self.localized_columns.is_empty() || self.locales.is_empty() {
            return format!("jsonb_build_object('*', {at})");
        }
        let text_array = |values: &[String]| {
            let quoted: Vec<String> = values.iter().map(|v| quote_literal(v)).collect();
            format!("ARRAY[{}]::text[]", quoted.join(", "))
        };
        format!(
            "COALESCE((SELECT jsonb_object_agg(lc.code, {at}) FROM unnest({locales}) AS lc(code) \
             WHERE EXISTS (SELECT 1 FROM unnest({columns}) AS lcol(name) \
             WHERE ({r} -> lcol.name -> lc.code) NOT IN \
             ('null'::jsonb, '\"\"'::jsonb, '{{}}'::jsonb, '[]'::jsonb))), '{{}}'::jsonb)",
            locales = text_array(&self.locales),
            columns = text_array(&self.localized_columns),
        )
    }

    /// `published_locales` and `scheduled_locales` for live row `r`, going live at `at`.
    fn publication(&self, r: &str, at: &str) -> (String, String) {
        let map = self.locale_map(r, at);
        (
            format!("CASE WHEN {at} <= now() THEN {map} ELSE '{{}}'::jsonb END"),
            format!("CASE WHEN {at} > now() THEN {map} ELSE '{{}}'::jsonb END"),
        )
    }

    fn relations(&self, schema: &str) -> (String, String) {
        (
            quote_qualified(schema, &self.table),
            quote_qualified(schema, &self.versions_table),
        )
    }

    /// True for a row `t` of the live table with no version row.
    fn unversioned(&self, schema: &str) -> String {
        let (_, versions) = self.relations(schema);
        format!(
            "NOT EXISTS (SELECT 1 FROM {versions} AS v WHERE v.\"record_id\" = t.{pk})",
            pk = quote_ident(&self.primary_key),
        )
    }

    /// Counts the live rows with no version row. With `versions_exist` false, the snapshot table
    /// is made by this push, so every row counts.
    pub fn count_sql(&self, schema: &str, versions_exist: bool) -> String {
        let (live, _) = self.relations(schema);
        if !versions_exist {
            return format!("SELECT count(*) FROM ONLY {live} AS t");
        }
        format!(
            "SELECT count(*) FROM ONLY {live} AS t WHERE {}",
            self.unversioned(schema)
        )
    }

    /// The statements that write version 1 for every live row with no version row. The guard
    /// trigger would number it, stamp the pushing session as its author and make it a draft, so
    /// the insert runs with the session's triggers off and they are back on before the next
    /// statement, as the flat-block move does.
    pub fn backfill_sql(&self, schema: &str) -> Vec<String> {
        let (live, versions) = self.relations(schema);
        let at = self.live_at("p.r");
        let (published, scheduled) = self.publication("p.r", "w.at");
        vec![
            "SET LOCAL session_replication_role = replica;".to_string(),
            format!(
                "INSERT INTO {versions} (\"record_id\", \"version\", \"status\", \"data\", \
                 \"created_by\", \"published_locales\", \"scheduled_locales\") \
                 SELECT b.record_id, 1, CASE WHEN b.published = '{{}}'::jsonb THEN 'draft' \
                 ELSE 'published' END, b.data, NULL, b.published, b.scheduled \
                 FROM (SELECT t.{pk} AS record_id, p.r AS data, {published} AS published, \
                 {scheduled} AS scheduled FROM ONLY {live} AS t \
                 CROSS JOIN LATERAL (SELECT to_jsonb(t) AS r) AS p \
                 CROSS JOIN LATERAL (SELECT {at} AS at) AS w WHERE {unversioned}) AS b;",
                pk = quote_ident(&self.primary_key),
                unversioned = self.unversioned(schema),
            ),
            "SET LOCAL session_replication_role = origin;".to_string(),
        ]
    }

    /// The trigger giving each row inserted into the live table its version 1, and its function.
    ///
    /// `AFTER INSERT`, so only a row actually inserted gets one: not an `ON CONFLICT DO NOTHING`
    /// that met an existing record, not the `DO UPDATE` arm of an upsert. `SECURITY DEFINER`
    /// because the inserting caller may hold no privilege on the snapshot table; the version is
    /// the system's record of the insert they made. The guard still numbers it 1, stamps the caller
    /// as its author and makes it a draft, and the update after it sets only the publishing state,
    /// which is all the guard lets an update change.
    pub fn trigger_sql(&self, schema: &str, name: &str) -> String {
        let (live, _) = self.relations(schema);
        format!(
            "{function}\
             REVOKE ALL ON FUNCTION {helper}.{name_q}() FROM PUBLIC;\n\n\
             DROP TRIGGER IF EXISTS {name_q} ON {live};\n\
             CREATE TRIGGER {name_q} AFTER INSERT ON {live}\n  \
             FOR EACH ROW EXECUTE FUNCTION {helper}.{name_q}();\n\n",
            function = self.trigger_function_sql(schema, name),
            helper = HELPER_SCHEMA,
            name_q = quote_ident(name),
        )
    }

    /// The function behind [`BaselineModel::trigger_sql`].
    fn trigger_function_sql(&self, schema: &str, name: &str) -> String {
        format!(
            "CREATE OR REPLACE FUNCTION {helper}.{name_q}() RETURNS trigger\n  \
             LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS {body};\n\n",
            helper = HELPER_SCHEMA,
            name_q = quote_ident(name),
            body = dollar_quote(&self.trigger_function_body(schema), "fn"),
        )
    }

    /// The body of [`BaselineModel::trigger_function_sql`], which names the model's tables.
    fn trigger_function_body(&self, schema: &str) -> String {
        let (_, versions) = self.relations(schema);
        let (published, scheduled) = self.publication("live", "live_at");
        format!(
            r#"
  DECLARE
    live jsonb := to_jsonb(NEW);
    live_at timestamptz := {at};
    published jsonb := {published};
    scheduled jsonb := {scheduled};
  BEGIN
    -- `create_record` writes version 1 itself, from what the caller typed.
    IF current_setting({setting}, true) = 'on' THEN
      RETURN NULL;
    END IF;
    IF EXISTS (SELECT 1 FROM {versions} v WHERE v."record_id" = NEW.{pk}) THEN
      RETURN NULL;
    END IF;
    INSERT INTO {versions} ("record_id", "data") VALUES (NEW.{pk}, live);
    UPDATE {versions} v
       SET "published_locales" = published, "scheduled_locales" = scheduled,
           "status" = CASE WHEN published = '{{}}'::jsonb THEN 'draft' ELSE 'published' END
     WHERE v."record_id" = NEW.{pk};
    RETURN NULL;
  END;
  "#,
            at = self.live_at("live"),
            setting = quote_literal(CREATING_RECORD_SETTING),
            pk = quote_ident(&self.primary_key),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(localized: bool) -> BaselineModel {
        BaselineModel {
            table: "talk".into(),
            versions_table: "talk_versions".into(),
            primary_key: "id".into(),
            localized_columns: if localized {
                vec!["abstract".into()]
            } else {
                Vec::new()
            },
            locales: vec!["en".into(), "fr".into()],
            has_published_at: true,
        }
    }

    #[test]
    fn a_whole_record_model_publishes_under_star() {
        assert_eq!(
            model(false).locale_map("r", "at"),
            "jsonb_build_object('*', at)"
        );
    }

    #[test]
    fn a_localized_model_publishes_the_locales_the_row_holds() {
        let map = model(true).locale_map("r", "at");
        assert!(map.contains("ARRAY['en', 'fr']::text[]"), "{map}");
        assert!(map.contains("ARRAY['abstract']::text[]"), "{map}");
    }

    #[test]
    fn the_backfill_runs_with_triggers_off_and_turns_them_back_on() {
        let sql = model(true).backfill_sql("public");
        assert_eq!(sql.len(), 3);
        assert!(sql[0].contains("replica"));
        assert!(sql[1].contains("NOT EXISTS"), "{}", sql[1]);
        assert!(sql[2].contains("origin"));
    }

    #[test]
    fn a_model_without_published_at_is_live_now() {
        let mut m = model(false);
        m.has_published_at = false;
        assert_eq!(m.live_at("r"), "now()");
    }
}
