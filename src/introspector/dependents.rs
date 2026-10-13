//! What depends on each column, as `pg_depend` records it: every index, constraint, trigger,
//! policy and view Postgres would drop with the column, or refuse to drop it for.
//!
//! A push that drops a column and adds it again (`RecreateColumn`) has to put these back, or
//! refuse when it cannot. Reading them off `pg_depend` finds the ones no other read attributes to
//! a column: an index that uses it only in an expression, in `INCLUDE` or in its `WHERE`, a check,
//! a unique constraint, a trigger that fires on it or tests it, a policy that reads it, a view
//! that selects it, and anything of another table, or another schema, that refers to it.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

/// One object that depends on a column of the project schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbColumnDependent {
    /// The table and column depended on.
    pub table: String,
    pub column: String,
    /// The schema and relation the object is on, or for a view, the view itself: `table` for most,
    /// another table's foreign key, a view anywhere.
    pub owner_schema: String,
    pub owner: String,
    pub name: String,
    pub kind: DependentKind,
    /// How the restore makes it again: `pg_get_indexdef` for an index, `pg_get_constraintdef` for
    /// a constraint, `pg_get_triggerdef` for a trigger (then, on a line of its own, the `ALTER
    /// TABLE` that puts back a state other than enabled on origin: disabled, replica or always,
    /// which `pg_get_triggerdef` leaves out), and for a policy what follows
    /// `CREATE POLICY name ON table` (` AS RESTRICTIVE FOR SELECT TO ... USING (...)`). Empty for a
    /// view, which is never made again.
    pub definition: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependentKind {
    /// An index of its own, not one a constraint makes and drops with itself.
    Index,
    ForeignKey,
    /// A primary key, unique, exclusion or check constraint.
    Constraint,
    Trigger,
    Policy,
    /// A view or materialized view (any rewrite rule) that reads the column.
    View,
}

/// The objects that depend on each column of `schema`, wherever they are. An index a constraint
/// owns is left out (the constraint is the dependent, and brings its index back with it), as is a
/// trigger Postgres makes for a key.
pub async fn read(conn: &mut PgConnection, schema: &str) -> Result<Vec<DbColumnDependent>> {
    let rows: Vec<DependentRow> = sqlx::query_as(&format!(
        r#"
        SELECT DISTINCT tbl.relname::text, att.attname::text, owner_ns.nspname::text,
               owner.relname::text, obj.name, obj.kind, obj.definition
          FROM pg_depend d
          JOIN pg_class tbl ON tbl.oid = d.refobjid
          JOIN pg_namespace ns ON ns.oid = tbl.relnamespace
          JOIN pg_attribute att ON att.attrelid = d.refobjid AND att.attnum = d.refobjsubid
          JOIN LATERAL ({}) obj ON true
          JOIN pg_class owner ON owner.oid = obj.owner_oid
          JOIN pg_namespace owner_ns ON owner_ns.oid = owner.relnamespace
         WHERE d.refclassid = 'pg_class'::regclass
           AND d.refobjsubid > 0
           AND ns.nspname = $1
           AND tbl.relkind IN ('r', 'p')
           AND {}
           AND {}
         ORDER BY 1, 2, 3, 4, 5
        "#,
        DEPENDENT_OBJECTS,
        super::readable("tbl.oid"),
        super::readable("owner.oid"),
    ))
    .bind(schema)
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter().map(DbColumnDependent::try_from).collect()
}

/// The object one `pg_depend` row `d` names, as `(owner_oid, name, kind, definition)`, whichever
/// catalog it is in.
const DEPENDENT_OBJECTS: &str = r#"
    SELECT con.conrelid AS owner_oid, con.conname::text AS name,
           CASE con.contype WHEN 'f' THEN 'foreign_key' ELSE 'constraint' END AS kind,
           pg_get_constraintdef(con.oid) AS definition
      FROM pg_constraint con
     WHERE d.classid = 'pg_constraint'::regclass AND con.oid = d.objid
       AND con.contype IN ('p', 'u', 'x', 'c', 'f')
    UNION ALL
    SELECT ix.indrelid, idx.relname::text, 'index', pg_get_indexdef(idx.oid)
      FROM pg_index ix
      JOIN pg_class idx ON idx.oid = ix.indexrelid
     WHERE d.classid = 'pg_class'::regclass AND ix.indexrelid = d.objid
       AND NOT EXISTS (
             SELECT 1 FROM pg_depend own
              WHERE own.classid = 'pg_class'::regclass AND own.objid = ix.indexrelid
                AND own.refclassid = 'pg_constraint'::regclass AND own.deptype = 'i')
    UNION ALL
    SELECT tg.tgrelid, tg.tgname::text, 'trigger',
           pg_get_triggerdef(tg.oid)
           || CASE tg.tgenabled
                WHEN 'D' THEN ';' || chr(10) || 'ALTER TABLE ' || tg.tgrelid::regclass::text
                              || ' DISABLE TRIGGER ' || quote_ident(tg.tgname)
                WHEN 'R' THEN ';' || chr(10) || 'ALTER TABLE ' || tg.tgrelid::regclass::text
                              || ' ENABLE REPLICA TRIGGER ' || quote_ident(tg.tgname)
                WHEN 'A' THEN ';' || chr(10) || 'ALTER TABLE ' || tg.tgrelid::regclass::text
                              || ' ENABLE ALWAYS TRIGGER ' || quote_ident(tg.tgname)
                ELSE ''
              END
      FROM pg_trigger tg
     WHERE d.classid = 'pg_trigger'::regclass AND tg.oid = d.objid AND NOT tg.tgisinternal
    UNION ALL
    SELECT pol.polrelid, pol.polname::text, 'policy',
           ' AS ' || CASE WHEN pol.polpermissive THEN 'PERMISSIVE' ELSE 'RESTRICTIVE' END
           || ' FOR ' || CASE pol.polcmd WHEN 'r' THEN 'SELECT' WHEN 'a' THEN 'INSERT'
                                         WHEN 'w' THEN 'UPDATE' WHEN 'd' THEN 'DELETE'
                                         ELSE 'ALL' END
           || ' TO ' || (SELECT string_agg(CASE WHEN r.oid = 0 THEN 'PUBLIC'
                                                ELSE quote_ident(rol.rolname) END,
                                           ', ' ORDER BY r.ord)
                           FROM unnest(pol.polroles) WITH ORDINALITY AS r(oid, ord)
                           LEFT JOIN pg_roles rol ON rol.oid = r.oid)
           || COALESCE(' USING (' || pg_get_expr(pol.polqual, pol.polrelid) || ')', '')
           || COALESCE(' WITH CHECK (' || pg_get_expr(pol.polwithcheck, pol.polrelid) || ')',
                       '')
      FROM pg_policy pol
     WHERE d.classid = 'pg_policy'::regclass AND pol.oid = d.objid
    UNION ALL
    SELECT rw.ev_class, view.relname::text, 'view', ''
      FROM pg_rewrite rw
      JOIN pg_class view ON view.oid = rw.ev_class
     WHERE d.classid = 'pg_rewrite'::regclass AND rw.oid = d.objid
"#;

type DependentRow = (String, String, String, String, String, String, String);

impl TryFrom<DependentRow> for DbColumnDependent {
    type Error = anyhow::Error;

    fn try_from(row: DependentRow) -> Result<Self> {
        let (table, column, owner_schema, owner, name, kind, definition) = row;
        Ok(DbColumnDependent {
            table,
            column,
            owner_schema,
            owner,
            name,
            kind: dependent_kind(&kind)?,
            definition,
        })
    }
}

fn dependent_kind(kind: &str) -> Result<DependentKind> {
    match kind {
        "index" => Ok(DependentKind::Index),
        "foreign_key" => Ok(DependentKind::ForeignKey),
        "constraint" => Ok(DependentKind::Constraint),
        "trigger" => Ok(DependentKind::Trigger),
        "policy" => Ok(DependentKind::Policy),
        "view" => Ok(DependentKind::View),
        other => anyhow::bail!("unexpected column dependent kind {other:?}"),
    }
}
