use crate::introspector::fingerprint::ObjectKind;
use crate::introspector::{
    constraints::DbConstraint, enums::DbEnum, indexes::DbIndex, rls::DbRlsPolicy, tables::DbTable,
    triggers::DbTrigger,
};
use crate::ledger::{LedgerRow, Status};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseState {
    pub schema: String,
    pub tables: Vec<DbTable>,
    pub indexes: Vec<DbIndex>,
    pub constraints: Vec<DbConstraint>,
    pub rls_policies: Vec<DbRlsPolicy>,
    pub triggers: Vec<DbTrigger>,
    pub extensions: Vec<String>,
    /// Postgres enum types discovered in this schema.
    #[serde(default)]
    pub enums: Vec<DbEnum>,
    /// Tables with row level security enabled, independent of whether they have
    /// any policies. Defaulted for snapshots written before this was recorded.
    #[serde(default)]
    pub rls_enabled_tables: Vec<String>,
    /// What the ledger says of each table it has a row for (Phase 4.11): true when Supatype's,
    /// false when released. Filled by the caller that read the ledger; never part of a snapshot.
    #[serde(skip)]
    pub table_ownership: BTreeMap<String, bool>,
    /// The same for each column the ledger has a row for, keyed by table and column (D4).
    #[serde(skip)]
    pub column_ownership: BTreeMap<(String, String), bool>,
}

impl DatabaseState {
    /// Whether `table` is Supatype's, so a push may drop it, drop its columns, rename it, or attach
    /// access rules to it. The ledger decides when it has a row; otherwise the ownership stamp an
    /// older engine wrote does (plan section 7), which the next push records.
    pub fn owns_table(&self, table: &DbTable) -> bool {
        self.table_ownership
            .get(&table.name)
            .copied()
            .unwrap_or_else(|| crate::managed::is_managed_comment(table.comment.as_deref()))
    }

    /// What the ledger says of `column` on `table`: `Some(true)` when Supatype's, `Some(false)`
    /// when released, `None` when it has no row.
    pub fn column_owned(&self, table: &str, column: &str) -> Option<bool> {
        self.column_ownership
            .get(&(table.to_string(), column.to_string()))
            .copied()
    }

    /// Takes each table's and each column's ownership from the ledger rows of `schema`.
    pub fn set_table_ownership(&mut self, ledger: &[LedgerRow]) {
        let schema = self.schema.as_str();
        let here = |kind| {
            ledger
                .iter()
                .filter(move |r: &&LedgerRow| r.key.kind == kind && r.key.schema == schema)
        };
        let table_ownership = here(ObjectKind::Table)
            .map(|r| (r.key.name.clone(), r.status != Status::Released))
            .collect();
        let column_ownership = here(ObjectKind::Column)
            .map(|r| {
                (
                    (r.key.parent.clone(), r.key.name.clone()),
                    r.status != Status::Released,
                )
            })
            .collect();
        self.table_ownership = table_ownership;
        self.column_ownership = column_ownership;
    }
}
