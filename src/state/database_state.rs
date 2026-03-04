use serde::{Deserialize, Serialize};
use crate::introspector::{
    tables::DbTable,
    indexes::DbIndex,
    constraints::DbConstraint,
    rls::DbRlsPolicy,
    triggers::DbTrigger,
};

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
}
