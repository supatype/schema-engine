use crate::introspector::fingerprint::ObjectKind;
use crate::introspector::{
    constraints::DbConstraint, enums::DbEnum, indexes::DbIndex, rls::DbRlsPolicy, tables::DbTable,
    triggers::DbTrigger,
};
use crate::ledger::{LedgerRow, Status};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
    /// The `(table, policy)` pairs of this schema the ledger records as Supatype's (not released):
    /// the reconcile's to keep or drop. Filled with `table_ownership`; never part of a snapshot.
    #[serde(skip)]
    pub owned_policies: BTreeSet<(String, String)>,
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

    /// Takes each table's ownership, and which policies are ours, from the ledger rows of `schema`.
    pub fn set_table_ownership(&mut self, ledger: &[LedgerRow]) {
        self.table_ownership = ledger
            .iter()
            .filter(|r| r.key.kind == ObjectKind::Table && r.key.schema == self.schema)
            .map(|r| (r.key.name.clone(), r.status != Status::Released))
            .collect();
        self.owned_policies = ledger
            .iter()
            .filter(|r| {
                r.key.kind == ObjectKind::Policy
                    && r.key.schema == self.schema
                    && r.status != Status::Released
            })
            .map(|r| (r.key.parent.clone(), r.key.name.clone()))
            .collect();
    }

    /// Whether a policy is Supatype's: the ledger records it, or it carries the stamp an older
    /// engine wrote. One that is, but that the schema no longer declares, is the reconcile's to
    /// drop, not a hand-written policy.
    pub fn owns_policy(&self, policy: &DbRlsPolicy) -> bool {
        policy.managed
            || self
                .owned_policies
                .contains(&(policy.table.clone(), policy.name.clone()))
    }
}
