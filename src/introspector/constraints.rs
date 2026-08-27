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
    pub foreign_columns: Option<Vec<String>>,
    pub check_expression: Option<String>,
    pub on_delete: Option<String>,
    /// Postgres `COMMENT ON CONSTRAINT` text, when set.
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum DbConstraintType {
    PrimaryKey,
    Unique,
    ForeignKey,
    Check,
}

pub async fn read(conn: &mut PgConnection, schema: &str) -> Result<Vec<DbConstraint>> {
    // Read all FK constraints
    let fk_rows: Vec<(String, String, String, String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT
            tc.table_name,
            tc.constraint_name,
            kcu.column_name,
            ccu.table_name  AS foreign_table,
            ccu.column_name AS foreign_column,
            rc.delete_rule
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name
           AND tc.table_schema    = kcu.table_schema
        JOIN information_schema.referential_constraints rc
            ON tc.constraint_name   = rc.constraint_name
           AND tc.constraint_schema = rc.constraint_schema
        JOIN information_schema.constraint_column_usage ccu
            ON rc.unique_constraint_name   = ccu.constraint_name
           AND rc.unique_constraint_schema = ccu.constraint_schema
        WHERE tc.table_schema = $1
          AND tc.constraint_type = 'FOREIGN KEY'
        ORDER BY tc.table_name, tc.constraint_name, kcu.ordinal_position
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *conn)
    .await?;

    // Group FK rows by (table, constraint_name)
    #[allow(clippy::type_complexity)]
    let mut fk_map: std::collections::HashMap<
        (String, String),
        (Vec<String>, String, Vec<String>, Option<String>),
    > = std::collections::HashMap::new();
    for (table, constraint, col, ftable, fcol, on_delete) in fk_rows {
        let entry = fk_map
            .entry((table.clone(), constraint.clone()))
            .or_insert_with(|| (vec![], ftable, vec![], on_delete));
        entry.0.push(col);
        entry.2.push(fcol);
    }

    let mut constraints: Vec<DbConstraint> = fk_map
        .into_iter()
        .map(
            |((table, name), (columns, foreign_table, foreign_columns, on_delete))| DbConstraint {
                table,
                name,
                constraint_type: DbConstraintType::ForeignKey,
                columns,
                foreign_table: Some(foreign_table),
                foreign_columns: Some(foreign_columns),
                check_expression: None,
                on_delete,
                comment: None,
            },
        )
        .collect();

    // Read UNIQUE constraints (with optional comment)
    let unique_rows: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT
            tc.table_name,
            tc.constraint_name,
            kcu.column_name,
            pg_catalog.obj_description(c.oid, 'pg_constraint')
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name
           AND tc.table_schema    = kcu.table_schema
        JOIN pg_catalog.pg_constraint c
            ON c.conname = tc.constraint_name
        JOIN pg_catalog.pg_class cl
            ON cl.oid = c.conrelid
        JOIN pg_catalog.pg_namespace n
            ON n.oid = cl.relnamespace AND n.nspname = tc.table_schema
        WHERE tc.table_schema    = $1
          AND tc.constraint_type = 'UNIQUE'
        ORDER BY tc.table_name, tc.constraint_name, kcu.ordinal_position
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *conn)
    .await?;

    let mut unique_map: std::collections::HashMap<(String, String), (Vec<String>, Option<String>)> =
        std::collections::HashMap::new();
    for (table, constraint, col, comment) in unique_rows {
        let entry = unique_map
            .entry((table.clone(), constraint.clone()))
            .or_insert_with(|| (vec![], comment));
        entry.0.push(col);
    }
    for ((table, name), (columns, comment)) in unique_map {
        constraints.push(DbConstraint {
            table,
            name,
            constraint_type: DbConstraintType::Unique,
            columns,
            foreign_table: None,
            foreign_columns: None,
            check_expression: None,
            on_delete: None,
            comment,
        });
    }

    // Read CHECK constraints from `pg_constraint` rather than `information_schema`, which exposes
    // neither the constraint's OID nor its comment. The comment is what makes a bound diffable: it
    // carries a fingerprint of the declared bound, so a tightened `MaxLength` is detected without
    // comparing SQL text that `pg_get_constraintdef` has already rewritten.
    let check_rows: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT
            rel.relname::text                                AS table_name,
            con.conname::text                                AS constraint_name,
            pg_get_constraintdef(con.oid)                    AS definition,
            obj_description(con.oid, 'pg_constraint')        AS comment
        FROM pg_constraint con
        JOIN pg_class rel      ON rel.oid = con.conrelid
        JOIN pg_namespace ns   ON ns.oid  = rel.relnamespace
        -- `contype = 'c'` is the whole filter. A column's NOT NULL never lands here: PG17 keeps it
        -- off `pg_constraint` entirely, and PG18 catalogues it as `contype = 'n'` reading `NOT NULL
        -- a`. Excluding definitions that merely mention `IS NOT NULL` would instead drop real
        -- bounds, since a model constraint may name a column as non-null inside a larger rule.
        WHERE ns.nspname = $1
          AND con.contype = 'c'
        ORDER BY rel.relname, con.conname
        "#,
    )
    .bind(schema)
    .fetch_all(&mut *conn)
    .await?;

    for (table, name, definition, comment) in check_rows {
        constraints.push(DbConstraint {
            table,
            name,
            constraint_type: DbConstraintType::Check,
            columns: vec![],
            foreign_table: None,
            foreign_columns: None,
            check_expression: Some(definition),
            on_delete: None,
            comment,
        });
    }

    Ok(constraints)
}
