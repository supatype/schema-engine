pub mod features;

pub struct License {
    tier: LicenseTier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseTier {
    Community,
    Pro,
    Enterprise,
}

impl License {
    pub fn new(key: Option<&str>) -> Self {
        // TODO: validate license key against licensing server / embedded public key
        let tier = match key {
            None => LicenseTier::Community,
            Some(_) => LicenseTier::Community, // placeholder until key validation implemented
        };
        Self { tier }
    }

    pub fn is_pro(&self) -> bool {
        matches!(self.tier, LicenseTier::Pro | LicenseTier::Enterprise)
    }

    pub fn is_enterprise(&self) -> bool {
        matches!(self.tier, LicenseTier::Enterprise)
    }
}
