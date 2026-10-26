use super::Operation;
use anyhow::Result;

/// Topologically sort operations so dependencies are satisfied:
/// CREATE TABLE before FKs, DROP FK before DROP TABLE, etc.
pub fn topological_sort(ops: Vec<Operation>) -> Result<Vec<Operation>> {
    // TODO: Phase 1: build dependency graph using petgraph and sort.
    // For Phase 0, return operations in a reasonable default order.
    let mut _ordered: Vec<Operation> = Vec::new();

    // Rough priority order without full graph
    let priority = |op: &Operation| match op {
        Operation::EnableExtension { .. } => 0,
        Operation::RenameTable { .. } => 4,
        Operation::CreateTable { .. } => 4,
        Operation::CreateJunctionTable { .. } => 5,
        // Same tier as a junction table, and for the same reason: it carries a foreign key to a
        // model table, which `CreateTable` above has just made exist.
        Operation::CreateVersionsTable { .. } => 5,
        Operation::AddColumn { .. } => 6,
        Operation::RenameColumn { .. } => 6,
        Operation::AlterColumn { .. } => 7,
        Operation::RecreateColumn { .. } => 7,
        Operation::AddForeignKey { .. } => 8,
        Operation::AddUniqueConstraint { .. } => 8,
        Operation::AddIndex { .. } => 9,
        Operation::EnableRls { .. } => 10,
        // Drop RLS policies BEFORE creating them, so a drop+recreate of the same
        // policy ends with the policy present (creates are idempotent DROP+CREATE).
        Operation::CreateRlsPolicy { .. } => 12,
        Operation::DropUniqueConstraint { .. } => 15,
        Operation::DropColumn { .. } => 17,
        Operation::DropTable { .. } => 18,
    };

    let mut indexed: Vec<(usize, Operation)> = ops.into_iter().enumerate().collect();
    indexed.sort_by_key(|(_, op)| priority(op));
    Ok(indexed.into_iter().map(|(_, op)| op).collect())
}
