use anyhow::Result;
use super::Operation;

/// Topologically sort operations so dependencies are satisfied:
/// CREATE TABLE before FKs, DROP FK before DROP TABLE, etc.
pub fn topological_sort(ops: Vec<Operation>) -> Result<Vec<Operation>> {
    // TODO: Phase 1 — build dependency graph using petgraph and sort.
    // For Phase 0, return operations in a reasonable default order.
    let mut _ordered: Vec<Operation> = Vec::new();

    // Rough priority order without full graph
    let priority = |op: &Operation| match op {
        Operation::EnableExtension { .. } => 0,
        Operation::CreateEnum { .. } => 1,
        Operation::CreateTable { .. } => 2,
        Operation::CreateJunctionTable { .. } => 3,
        Operation::AddColumn { .. } => 4,
        Operation::RenameColumn { .. } => 4,
        Operation::AlterColumn { .. } => 5,
        Operation::AddForeignKey { .. } => 6,
        Operation::AddIndex { .. } => 7,
        Operation::EnableRls { .. } => 8,
        Operation::CreateRlsPolicy { .. } => 9,
        Operation::CreateTrigger { .. } => 10,
        Operation::DropRlsPolicy { .. } => 11,
        Operation::DropTrigger { .. } => 12,
        Operation::DropForeignKey { .. } => 13,
        Operation::DropIndex { .. } => 14,
        Operation::DropColumn { .. } => 15,
        Operation::DropTable { .. } => 16,
        Operation::DropEnum { .. } => 17,
    };

    let mut indexed: Vec<(usize, Operation)> = ops.into_iter().enumerate().collect();
    indexed.sort_by_key(|(_, op)| priority(op));
    Ok(indexed.into_iter().map(|(_, op)| op).collect())
}
