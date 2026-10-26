use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbIndex {
    pub table: String,
    pub name: String,
    /// The column keys, in key order. Empty for an index made only of expressions. `INCLUDE`
    /// columns are not keys and are in [`Self::include`].
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
    /// The `INCLUDE` columns, in order.
    #[serde(default)]
    pub include: Vec<String>,
    /// What each key does beyond naming its column or expression, for the keys that do anything:
    /// `{position} {options}`, comma-separated, where the options are any of a collation other
    /// than the column's (an expression's: its type's), an operator class that is not the type's
    /// default (both schema-qualified), `DESC`, and a `NULLS` order other than the direction's
    /// default. Empty for an index of plain keys. `2 DESC` for `(record_id, version DESC)`.
    #[serde(default)]
    pub options: String,
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
    Option<Vec<String>>,
    Option<String>,
);

pub async fn read_all(conn: &mut PgConnection, schema: &str) -> Result<DbIndexes> {
    let rows: Vec<IndexRow> = sqlx::query_as(&format!(
        "SELECT t.relname::text, i.relname::text,
                (SELECT array_agg(a.attname::text ORDER BY k.ord)
                   FROM unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ord)
                   JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
                  WHERE k.attnum <> 0 AND k.ord <= ix.indnkeyatts),
                ix.indisunique, am.amname::text, ix.indisprimary,
                pg_catalog.obj_description(i.oid, 'pg_class'),
                pg_get_expr(ix.indexprs, ix.indrelid),
                pg_get_expr(ix.indpred, ix.indrelid),
                pg_get_indexdef(i.oid),
                (SELECT array_agg(a.attname::text ORDER BY k.ord)
                   FROM unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ord)
                   JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
                  WHERE k.ord > ix.indnkeyatts),
                -- `indoption` bit 0 is DESC, bit 1 NULLS FIRST; ASC defaults to NULLS LAST and
                -- DESC to NULLS FIRST. A key's collation is its own when it is the column's (or,
                -- for an expression, its type's).
                (SELECT string_agg(k.ord || ' ' || concat_ws(' ',
                            CASE WHEN k.coll <> 0 AND k.coll <> COALESCE(ta.attcollation, kt.typcollation)
                                 THEN 'COLLATE ' || quote_ident(cn.nspname) || '.' || quote_ident(co.collname) END,
                            CASE WHEN NOT oc.opcdefault
                                 THEN quote_ident(ocn.nspname) || '.' || quote_ident(oc.opcname) END,
                            CASE WHEN k.opt & 1 <> 0 THEN 'DESC' END,
                            CASE WHEN k.opt & 1 = 0 AND k.opt & 2 <> 0 THEN 'NULLS FIRST'
                                 WHEN k.opt & 1 <> 0 AND k.opt & 2 = 0 THEN 'NULLS LAST' END),
                          ',' ORDER BY k.ord)
                   FROM unnest(ix.indkey::int2[], ix.indclass::oid[], ix.indcollation::oid[],
                               ix.indoption::int2[])
                        WITH ORDINALITY AS k(attnum, opclass, coll, opt, ord)
                   JOIN pg_attribute ka ON ka.attrelid = i.oid AND ka.attnum = k.ord
                   LEFT JOIN pg_attribute ta ON ta.attrelid = t.oid AND ta.attnum = k.attnum
                                            AND k.attnum <> 0
                   JOIN pg_type kt ON kt.oid = ka.atttypid
                   JOIN pg_opclass oc ON oc.oid = k.opclass
                   JOIN pg_namespace ocn ON ocn.oid = oc.opcnamespace
                   LEFT JOIN pg_collation co ON co.oid = k.coll
                   LEFT JOIN pg_namespace cn ON cn.oid = co.collnamespace
                  WHERE (k.coll <> 0 AND k.coll <> COALESCE(ta.attcollation, kt.typcollation))
                     OR NOT oc.opcdefault
                     OR k.opt & 3 <> 0)
         FROM pg_class t
         JOIN pg_index ix ON t.oid = ix.indrelid
         JOIN pg_class i ON i.oid = ix.indexrelid
         JOIN pg_am am ON am.oid = i.relam
         JOIN pg_namespace n ON n.oid = t.relnamespace
         WHERE n.nspname = $1 AND ix.indisvalid AND {}
         ORDER BY t.relname, i.relname",
        super::readable("t.oid"),
    ))
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
        include,
        options,
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
            include: include.unwrap_or_default(),
            options: options.unwrap_or_default(),
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
