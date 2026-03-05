use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum DbConstraintType {
    PrimaryKey,
    Unique,
    ForeignKey,
    Check,
}

pub async fn read(pool: &PgPool, schema: &str) -> Result<Vec<DbConstraint>> {
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
    .fetch_all(pool)
    .await?;

    // Group FK rows by (table, constraint_name)
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
        .map(|((table, name), (columns, foreign_table, foreign_columns, on_delete))| {
            DbConstraint {
                table,
                name,
                constraint_type: DbConstraintType::ForeignKey,
                columns,
                foreign_table: Some(foreign_table),
                foreign_columns: Some(foreign_columns),
                check_expression: None,
                on_delete,
            }
        })
        .collect();

    // Read UNIQUE constraints
    let unique_rows: Vec<(String, String, String)> = sqlx::query_as(
        r#"
        SELECT
            tc.table_name,
            tc.constraint_name,
            kcu.column_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name
           AND tc.table_schema    = kcu.table_schema
        WHERE tc.table_schema    = $1
          AND tc.constraint_type = 'UNIQUE'
        ORDER BY tc.table_name, tc.constraint_name, kcu.ordinal_position
        "#,
    )
    .bind(schema)
    .fetch_all(pool)
    .await?;

    let mut unique_map: std::collections::HashMap<(String, String), Vec<String>> =
        std::collections::HashMap::new();
    for (table, constraint, col) in unique_rows {
        unique_map
            .entry((table, constraint))
            .or_default()
            .push(col);
    }
    for ((table, name), columns) in unique_map {
        constraints.push(DbConstraint {
            table,
            name,
            constraint_type: DbConstraintType::Unique,
            columns,
            foreign_table: None,
            foreign_columns: None,
            check_expression: None,
            on_delete: None,
        });
    }

    // Read CHECK constraints (excluding NOT NULL, which are not in table_constraints)
    let check_rows: Vec<(String, String, String)> = sqlx::query_as(
        r#"
        SELECT
            tc.table_name,
            tc.constraint_name,
            cc.check_clause
        FROM information_schema.table_constraints tc
        JOIN information_schema.check_constraints cc
            ON tc.constraint_name   = cc.constraint_name
           AND tc.constraint_schema = cc.constraint_schema
        WHERE tc.table_schema = $1
          AND tc.constraint_type = 'CHECK'
          AND cc.check_clause NOT LIKE '% IS NOT NULL'
        ORDER BY tc.table_name, tc.constraint_name
        "#,
    )
    .bind(schema)
    .fetch_all(pool)
    .await?;

    for (table, name, check_clause) in check_rows {
        constraints.push(DbConstraint {
            table,
            name,
            constraint_type: DbConstraintType::Check,
            columns: vec![],
            foreign_table: None,
            foreign_columns: None,
            check_expression: Some(check_clause),
            on_delete: None,
        });
    }

    Ok(constraints)
}
