//! What the engine creates but [`crate::state::database_state::DatabaseState`] does not carry.
//!
//! `DatabaseState` is what every differ reads, and seventy-odd tests build it by hand, so a field
//! added there is a field every one of them must name. This struct holds the kinds the ledger
//! (`plans/Managed-Object-Ownership-Plan.md`) needs to see and nothing diffs against yet. It is
//! read beside `DatabaseState`, not inside it, and the two merge when the ledger gives the differ
//! a reason to read these.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

use super::indexes::{self, DbExpressionIndex};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogState {
    /// Indexes made only of expressions, which `DatabaseState::indexes` cannot see.
    pub expression_indexes: Vec<DbExpressionIndex>,
}

pub async fn read(conn: &mut PgConnection, schema: &str) -> Result<CatalogState> {
    let indexes = indexes::read_all(conn, schema).await?;
    Ok(CatalogState {
        expression_indexes: indexes.expression_only,
    })
}
