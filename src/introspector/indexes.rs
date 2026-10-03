use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbIndex {
    pub table: String,
    pub name: String,
    /// The column keys, in key order. Empty for an index made only of expressions.
    pub columns: Vec<String>,
    pub unique: bool,
    pub method: String,
    pub is_primary: bool,
    /// Postgres `COMMENT ON INDEX` text, when set.
    #[serde(default)]
    pub comment: Option<String>,
    /// The expression keys, as `pg_get_expr` renders them, when the index has any.
    #[serde(default)]
    pub expressions: Option<String>,
    /// The `WHERE` clause of a partial index, as `pg_get_expr` renders it.
    #[serde(default)]
    pub predicate: Option<String>,
    /// The whole `CREATE INDEX` statement, from `pg_get_indexdef`.
    #[serde(default)]
    pub definition: Option<String>,
}

/// Every index in `schema`, split by whether it has a column key.
///
/// The split exists because of what the differ does with a managed index it cannot account for:
/// it drops it. An index made only of expressions, such as the `((TRUE))` a singleton model gets,
/// carries a managed comment and sits in no expected set, and the `pg_attribute` inner join in the
/// old query is what hid it and so kept it alive. So `DatabaseState::indexes` keeps receiving only
/// the columnar ones, and the expression-only ones are read into a list nothing diffs against
/// until the ledger owns indexes and expects them.
pub struct DbIndexes {
    pub columnar: Vec<DbIndex>,
    pub expression_only: Vec<DbIndex>,
}

type IndexRow = (
    String,
    String,
    Option<Vec<String>>,
    bool,
    String,
    bool,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
);

pub async fn read_all(conn: &mut PgConnection, schema: &str) -> Result<DbIndexes> {
    let rows: Vec<IndexRow> = sqlx::query_as(
        "SELECT t.relname::text, i.relname::text,
                (SELECT array_agg(a.attname::text ORDER BY k.ord)
                   FROM unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ord)
                   JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
                  WHERE k.attnum <> 0),
                ix.indisunique, am.amname::text, ix.indisprimary,
                pg_catalog.obj_description(i.oid, 'pg_class'),
                pg_get_expr(ix.indexprs, ix.indrelid),
                pg_get_expr(ix.indpred, ix.indrelid),
                pg_get_indexdef(i.oid)
         FROM pg_class t
         JOIN pg_index ix ON t.oid = ix.indrelid
         JOIN pg_class i ON i.oid = ix.indexrelid
         JOIN pg_am am ON am.oid = i.relam
         JOIN pg_namespace n ON n.oid = t.relnamespace
         WHERE n.nspname = $1
         ORDER BY t.relname, i.relname",
    )
    .bind(schema)
    .fetch_all(&mut *conn)
    .await?;

    let mut columnar = Vec::new();
    let mut expression_only = Vec::new();
    for (
        table,
        name,
        columns,
        unique,
        method,
        is_primary,
        comment,
        expressions,
        predicate,
        definition,
    ) in rows
    {
        let index = DbIndex {
            table,
            name,
            columns: columns.unwrap_or_default(),
            unique,
            method,
            is_primary,
            comment,
            expressions,
            predicate,
            definition: Some(definition),
        };
        if index.columns.is_empty() {
            expression_only.push(index);
        } else {
            columnar.push(index);
        }
    }
    Ok(DbIndexes {
        columnar,
        expression_only,
    })
}

/// The indexes with at least one column key, which is what every differ reads today.
pub async fn read(conn: &mut PgConnection, schema: &str) -> Result<Vec<DbIndex>> {
    Ok(read_all(conn, schema).await?.columnar)
}
