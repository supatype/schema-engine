use anyhow::Result;
use crate::parser::ast::SchemaAst;
use crate::state::database_state::DatabaseState;
use super::Operation;

pub fn diff(_ast: &SchemaAst, _db: &DatabaseState, _ops: &mut Vec<Operation>) -> Result<()> {
    // Trigger generation is deferred to Phase 1 (supatype-engine generate --triggers).
    // Emitting stub comments here breaks idempotency since triggers are never actually created.
    Ok(())
}
