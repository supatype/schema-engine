use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbConstraint {
    pub table: String,
    pub name: String,
    pub constraint_type: DbConstraintType,
    pub columns: Vec<String>,
    pub foreign_table: Option<String>,
    /// The schema of `foreign_table`. A relation to `supatype:user` points at `auth.users`, and
    /// without this it reads the same as one pointing at a `users` table in the project schema.
    #[serde(default)]
    pub foreign_schema: Option<String>,
    pub foreign_columns: Option<Vec<String>>,
    pub check_expression: Option<String>,
    pub on_delete: Option<String>,
    /// `pg_get_constraintdef`, for a foreign key: what the parts above leave out (`ON UPDATE`,
    /// `MATCH`, `DEFERRABLE`, `NOT VALID`) is in here, and enters its fingerprint.
    #[serde(default)]
    pub definition: Option<String>,
    /// Postgres `COMMENT ON CONSTRAINT` text, when set.
    #[serde(default)]
    pub comment: Option<String>,
    /// What a foreign key does besides `ON DELETE`, read from the catalog; `None` for the other
    /// kinds. Fingerprinted as parts of their own so a key that differs only in one of them reads
    /// as a different key, not as ours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foreign_key_options: Option<ForeignKeyOptions>,
}

/// A foreign key's `ON UPDATE`, `MATCH` and deferral, as `pg_constraint` records them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ForeignKeyOptions {
    /// Spelled as [`DbConstraint::on_delete`] is: `NO ACTION`, `RESTRICT`, `CASCADE`, ...
    pub on_update: String,
    /// `SIMPLE`, `FULL` or `PARTIAL`.
    pub match_type: String,
    pub deferrable: bool,
    pub initially_deferred: bool,
}

impl Default for ForeignKeyOptions {
    /// What a foreign key declared with none of these clauses has.
    fn default() -> Self {
        ForeignKeyOptions {
            on_update: "NO ACTION".into(),
            match_type: "SIMPLE".into(),
            deferrable: false,
            initially_deferred: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum DbConstraintType {
    PrimaryKey,
    Unique,
    ForeignKey,
    Check,
}

type ConstraintRow = (
    String,
    String,
    String,
    Option<Vec<String>>,
    Option<String>,
    Option<String>,
    Option<Vec<String>>,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    String,
    bool,
    bool,
);

/// The `ON DELETE` (or `ON UPDATE`) action as `information_schema.referential_constraints` spells it,
/// which is the spelling the generator splices back into `ALTER TABLE ... ADD CONSTRAINT`.
fn delete_rule(confdeltype: &str) -> Option<String> {
    let rule = match confdeltype {
        "a" => "NO ACTION",
        "r" => "RESTRICT",
        "c" => "CASCADE",
        "n" => "SET NULL",
        "d" => "SET DEFAULT",
        _ => return None,
    };
    Some(rule.to_string())
}

/// `MATCH` as SQL spells it, from `pg_constraint.confmatchtype`.
fn match_type(confmatchtype: &str) -> String {
    match confmatchtype {
        "f" => "FULL",
        "p" => "PARTIAL",
        _ => "SIMPLE",
    }
    .to_string()
}

/// Every primary key, unique, foreign key and check constraint on a table in `schema`.
///
/// One query over `pg_constraint`, where the previous three were split across
/// `information_schema` and `pg_constraint` and disagreed about what they could see:
///
/// - primary keys were never read, so nothing downstream could reason about them;
/// - foreign keys came from `information_schema`, which has no OID and so no comment, and the
///   comment was hard-coded to `None`;
/// - unique constraints were joined to `pg_constraint` on `conname` alone, so a constraint of the
///   same name on another table could supply the comment.
///
/// Output for unique, foreign key and check constraints is unchanged in shape and spelling. Check
/// constraints keep an empty `columns` list, as before: their consumers fingerprint the expression,
/// and the doctor report prints `columns` as the item's fields, so filling it would change that
/// output in a change meant to be read-only.
pub async fn read(conn: &mut PgConnection, schema: &str) -> Result<Vec<DbConstraint>> {
    let rows: Vec<ConstraintRow> = sqlx::query_as(
        r#"
        SELECT
            rel.relname::text,
            con.conname::text,
            con.contype::text,
            (SELECT array_agg(a.attname::text ORDER BY k.ord)
               FROM unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord)
               JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum),
            frel.relname::text,
            fns.nspname::text,
            (SELECT array_agg(a.attname::text ORDER BY k.ord)
               FROM unnest(con.confkey) WITH ORDINALITY AS k(attnum, ord)
               JOIN pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = k.attnum),
            NULLIF(con.confdeltype::text, ' '),
            pg_get_constraintdef(con.oid),
            obj_description(con.oid, 'pg_constraint'),
            NULLIF(con.confupdtype::text, ' '),
            con.confmatchtype::text,
            con.condeferrable,
            con.condeferred
        FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        JOIN pg_namespace ns ON ns.oid = rel.relnamespace
        LEFT JOIN pg_class frel ON frel.oid = con.confrelid
        LEFT JOIN pg_namespace fns ON fns.oid = frel.relnamespace
        -- `contype` is the whole filter. A column's NOT NULL never lands here: PG17 keeps it off
        -- `pg_constraint` entirely, and PG18 catalogues it as `contype = 'n'`.
        WHERE ns.nspname = $1
          AND con.contype IN ('p', 'u', 'f', 'c')
        ORDER BY rel.relname, con.conname
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *conn)
    .await?;

    let mut constraints = Vec::with_capacity(rows.len());
    for (
        table,
        name,
        contype,
        columns,
        foreign_table,
        foreign_schema,
        foreign_columns,
        confdeltype,
        definition,
        comment,
        confupdtype,
        confmatchtype,
        condeferrable,
        condeferred,
    ) in rows
    {
        let constraint = match contype.as_str() {
            "p" => DbConstraint {
                table,
                name,
                constraint_type: DbConstraintType::PrimaryKey,
                columns: columns.unwrap_or_default(),
                foreign_table: None,
                foreign_schema: None,
                foreign_columns: None,
                check_expression: None,
                on_delete: None,
                definition: None,
                comment,
                foreign_key_options: None,
            },
            "u" => DbConstraint {
                table,
                name,
                constraint_type: DbConstraintType::Unique,
                columns: columns.unwrap_or_default(),
                foreign_table: None,
                foreign_schema: None,
                foreign_columns: None,
                check_expression: None,
                on_delete: None,
                definition: None,
                comment,
                foreign_key_options: None,
            },
            "f" => DbConstraint {
                table,
                name,
                constraint_type: DbConstraintType::ForeignKey,
                columns: columns.unwrap_or_default(),
                foreign_table,
                foreign_schema,
                foreign_columns: Some(foreign_columns.unwrap_or_default()),
                check_expression: None,
                on_delete: confdeltype.as_deref().and_then(delete_rule),
                definition: Some(definition),
                comment,
                foreign_key_options: Some(ForeignKeyOptions {
                    on_update: confupdtype
                        .as_deref()
                        .and_then(delete_rule)
                        .unwrap_or_else(|| "NO ACTION".into()),
                    match_type: match_type(&confmatchtype),
                    deferrable: condeferrable,
                    initially_deferred: condeferred,
                }),
            },
            _ => DbConstraint {
                table,
                name,
                constraint_type: DbConstraintType::Check,
                columns: Vec::new(),
                foreign_table: None,
                foreign_schema: None,
                foreign_columns: None,
                check_expression: Some(definition),
                on_delete: None,
                definition: None,
                comment,
                foreign_key_options: None,
            },
        };
        constraints.push(constraint);
    }

    Ok(constraints)
}
