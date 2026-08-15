use crate::introspector::{
    constraints::DbConstraint, enums::DbEnum, indexes::DbIndex, rls::DbRlsPolicy, tables::DbTable,
    triggers::DbTrigger,
};
use serde::{Deserialize, Serialize};

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
}
