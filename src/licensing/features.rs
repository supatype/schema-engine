use super::{License, LicenseTier};

pub enum Feature {
    /// Pre-flight checks against production data
    MigrationSafetyAnalysis,
    /// ML-assisted rename detection confidence scoring
    AdvancedRenameDetection,
    /// Row count impact estimates for dry-runs
    MigrationDryRun,
    /// Multi-database migration generation
    MultiDatabase,
    /// Pre/post migration hooks
    CustomMigrationHooks,
    /// Full audit trail of schema changes
    AuditTrail,
    /// Parallel processing for large schemas
    PriorityDiffing,
    /// Require sign-off before applying
    MigrationApprovalWorkflow,
}

impl Feature {
    pub fn required_tier(&self) -> LicenseTier {
        match self {
            Feature::MigrationSafetyAnalysis
            | Feature::AdvancedRenameDetection
            | Feature::MigrationDryRun => LicenseTier::Pro,

            Feature::MultiDatabase
            | Feature::CustomMigrationHooks
            | Feature::AuditTrail
            | Feature::PriorityDiffing
            | Feature::MigrationApprovalWorkflow => LicenseTier::Enterprise,
        }
    }
}

impl License {
    pub fn can_use(&self, feature: &Feature) -> bool {
        match feature.required_tier() {
            LicenseTier::Community => true,
            LicenseTier::Pro => self.is_pro(),
            LicenseTier::Enterprise => self.is_enterprise(),
        }
    }
}
