use super::Operation;
use anyhow::Result;

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
        // Enum mutations must happen before table/column changes that reference them,
        // but after CreateEnum (which creates brand-new types).
        Operation::AddEnumValue { .. } => 2,
        Operation::RenameEnumValue { .. } => 2,
        // RemoveEnumValue and ReorderEnumValues recreate the type and alter columns,
        // so they run early but after additions.
        Operation::RemoveEnumValue { .. } => 3,
        Operation::ReorderEnumValues { .. } => 3,
        Operation::CreateTable { .. } => 4,
        Operation::CreateJunctionTable { .. } => 5,
        Operation::AddColumn { .. } => 6,
        Operation::RenameColumn { .. } => 6,
        Operation::AlterColumn { .. } => 7,
        Operation::AddForeignKey { .. } => 8,
        Operation::AddIndex { .. } => 9,
        Operation::EnableRls { .. } => 10,
        Operation::CreateRlsPolicy { .. } => 11,
        Operation::CreateTrigger { .. } => 12,
        Operation::DropRlsPolicy { .. } => 13,
        Operation::DropTrigger { .. } => 14,
        Operation::DropForeignKey { .. } => 15,
        Operation::DropIndex { .. } => 16,
        Operation::DropColumn { .. } => 17,
        Operation::DropTable { .. } => 18,
        Operation::DropEnum { .. } => 19,
    };

    let mut indexed: Vec<(usize, Operation)> = ops.into_iter().enumerate().collect();
    indexed.sort_by_key(|(_, op)| priority(op));
    Ok(indexed.into_iter().map(|(_, op)| op).collect())
}
