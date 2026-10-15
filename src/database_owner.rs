//! What a push makes in the project schema belongs to the database's owner (SEC-SQL, SQ1a).
//!
//! A project database is owned by a role that is not a superuser: the demoted `postgres` on
//! self-host, `<ref>_owner` on Cloud. The engine connects as a superuser all the same, because the
//! extensions it installs need one, so every relation it creates starts out the superuser's. Left
//! there, the owner and its members (Studio's SQL editor among them) could neither alter nor read
//! the project's own tables. So inside the push's transaction, before the push reads back what it
//! made, each relation of the project schema the connecting role owns is handed to the owner,
//! resolved from `pg_database.datdba` rather than named, so one engine serves both hosts.
//!
//! Only the connecting role's own relations move: the `api` views stay with their own owner, and
//! objects an extension made stay with the extension. A serial's sequence moves with its table.
//! Nothing happens when the connecting role is the owner, or cannot act as it.

use anyhow::{Context, Result};
use sqlx::{Executor, PgConnection};

use crate::sql_quote::quote_literal;

/// The `DO` block that hands `schema`'s relations to the database's owner.
pub fn hand_to_owner_sql(schema: &str) -> String {
    format!(
        "DO $owner$
DECLARE
  owner name := (SELECT pg_get_userbyid(datdba) FROM pg_database
                  WHERE datname = current_database());
  rel record;
BEGIN
  IF owner = current_user OR NOT pg_has_role(current_user, owner, 'MEMBER') THEN
    RETURN;
  END IF;
  FOR rel IN
    SELECT c.oid::regclass AS name,
           CASE c.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW'
                          WHEN 'S' THEN 'SEQUENCE' WHEN 'f' THEN 'FOREIGN TABLE'
                          ELSE 'TABLE' END AS kind
      FROM pg_class c
     WHERE c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = {schema})
       AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
       AND c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
       AND NOT EXISTS (
             SELECT 1 FROM pg_depend d
              WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid
                AND (d.deptype = 'e'
                     OR (c.relkind = 'S' AND d.deptype IN ('a', 'i')
                         AND d.refclassid = 'pg_class'::regclass)))
  LOOP
    EXECUTE format('ALTER %s %s OWNER TO %I', rel.kind, rel.name, owner);
  END LOOP;
END
$owner$;",
        schema = quote_literal(schema),
    )
}

/// Runs [`hand_to_owner_sql`] for `schema` on `conn`, the push's transaction.
pub async fn hand_to_owner(conn: &mut PgConnection, schema: &str) -> Result<()> {
    conn.execute(sqlx::raw_sql(&hand_to_owner_sql(schema)))
        .await
        .context("Failed to hand the project schema's relations to the database's owner")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schema_is_quoted_as_a_literal() {
        let sql = hand_to_owner_sql("it's");
        assert!(sql.contains("WHERE nspname = 'it''s')"), "{sql}");
    }
}
