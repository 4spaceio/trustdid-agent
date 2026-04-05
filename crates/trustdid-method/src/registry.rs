use std::collections::HashMap;
use std::sync::Arc;
use trustdid_core::{LedgerDriver, Network, Result, TrustDIDError};

/// Registry of ledger drivers, mapping network types to their implementations.
pub struct DriverRegistry {
    evm_drivers: HashMap<u64, Arc<dyn LedgerDriver>>,
    keri_driver: Option<Arc<dyn LedgerDriver>>,
    web_drivers: HashMap<String, Arc<dyn LedgerDriver>>,
    default_web_driver: Option<Arc<dyn LedgerDriver>>,
}

impl DriverRegistry {
    pub fn new() -> Self {
        Self {
            evm_drivers: HashMap::new(),
            keri_driver: None,
            web_drivers: HashMap::new(),
            default_web_driver: None,
        }
    }

    pub fn register_evm(&mut self, chain_id: u64, driver: Arc<dyn LedgerDriver>) {
        self.evm_drivers.insert(chain_id, driver);
    }

    pub fn register_keri(&mut self, driver: Arc<dyn LedgerDriver>) {
        self.keri_driver = Some(driver);
    }

    pub fn register_web(&mut self, domain: impl Into<String>, driver: Arc<dyn LedgerDriver>) {
        self.web_drivers.insert(domain.into(), driver);
    }

    pub fn register_default_web(&mut self, driver: Arc<dyn LedgerDriver>) {
        self.default_web_driver = Some(driver);
    }

    pub fn driver_for(&self, network: &Network) -> Result<Arc<dyn LedgerDriver>> {
        match network {
            Network::Evm(chain_id) => self
                .evm_drivers
                .get(chain_id)
                .cloned()
                .ok_or_else(|| TrustDIDError::UnsupportedNetwork(format!("evm:{chain_id}"))),

            Network::Keri => self
                .keri_driver
                .clone()
                .ok_or_else(|| TrustDIDError::UnsupportedNetwork("keri".into())),

            Network::Web(domain) => self
                .web_drivers
                .get(domain)
                .cloned()
                .or_else(|| self.default_web_driver.clone())
                .ok_or_else(|| TrustDIDError::UnsupportedNetwork(format!("web:{domain}"))),
        }
    }

    pub fn supported_networks(&self) -> Vec<String> {
        let mut networks: Vec<String> = Vec::new();
        for chain_id in self.evm_drivers.keys() {
            networks.push(format!("evm:{chain_id}"));
        }
        if self.keri_driver.is_some() {
            networks.push("keri".to_string());
        }
        for domain in self.web_drivers.keys() {
            networks.push(format!("web:{domain}"));
        }
        networks.sort();
        networks
    }
}

impl Default for DriverRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use trustdid_core::*;

    struct DummyDriver(&'static str);

    #[async_trait]
    impl LedgerDriver for DummyDriver {
        fn network_id(&self) -> &str {
            self.0
        }
        async fn anchor(&self, _: &DID, _: &DIDDocument) -> Result<AnchorReceipt> {
            unimplemented!()
        }
        async fn retrieve(&self, _: &DID) -> Result<Option<DIDDocument>> {
            unimplemented!()
        }
        async fn update(&self, _: &DID, _: &DIDDocument, _: &Proof) -> Result<AnchorReceipt> {
            unimplemented!()
        }
        async fn deactivate(&self, _: &DID, _: &Proof) -> Result<()> {
            unimplemented!()
        }
    }

    #[test]
    fn test_driver_registry() {
        let mut reg = DriverRegistry::new();
        reg.register_evm(1, Arc::new(DummyDriver("evm:1")));
        reg.register_evm(137, Arc::new(DummyDriver("evm:137")));
        reg.register_keri(Arc::new(DummyDriver("keri")));
        reg.register_web("example.com", Arc::new(DummyDriver("web:example.com")));

        assert!(reg.driver_for(&Network::Evm(1)).is_ok());
        assert!(reg.driver_for(&Network::Evm(137)).is_ok());
        assert!(reg.driver_for(&Network::Keri).is_ok());
        assert!(reg.driver_for(&Network::Web("example.com".into())).is_ok());

        // Not registered
        assert!(reg.driver_for(&Network::Evm(42)).is_err());
        assert!(reg.driver_for(&Network::Web("unknown.com".into())).is_err());
    }

    #[test]
    fn test_supported_networks() {
        let mut reg = DriverRegistry::new();
        reg.register_evm(1, Arc::new(DummyDriver("evm:1")));
        reg.register_keri(Arc::new(DummyDriver("keri")));

        let networks = reg.supported_networks();
        assert!(networks.contains(&"evm:1".to_string()));
        assert!(networks.contains(&"keri".to_string()));
    }
}
