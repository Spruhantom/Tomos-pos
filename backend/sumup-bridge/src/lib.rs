//! SumUp Cloud API adapter for TomOS POS.
//!
//! This crate deliberately handles payment-provider communication only. It never
//! stores cardholder data and does not mark a sale paid; the POS domain must wait
//! for the final, correlated transaction result.

mod client;
mod config;
mod error;
mod models;

pub use client::SumUpClient;
pub use config::SumUpConfig;
pub use error::{Result, SumUpError};
pub use models::{CheckoutRequest, Reader, ReaderStatus};

/// Provider identity used by the POS payment-adapter registry.
pub const PROVIDER_ID: &str = "sumup";

/// Supported integration paths. Device support is capability-driven rather than
/// inferred from a marketing name or assumed to share one transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrationPath {
    /// Remote, server-driven integration for Solo-family readers.
    CloudApi,
    /// Native mobile reader SDK integration, normally hosted by a companion app.
    MobileReaderSdk,
    /// Legacy hand-off to the SumUp app where supported.
    PaymentSwitch,
}

/// Explicit capabilities exposed to the POS UI and checkout orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalCapabilities {
    pub remote_checkout: bool,
    pub reader_management: bool,
    pub asynchronous_result: bool,
    pub requires_companion_app: bool,
}

impl IntegrationPath {
    pub const fn capabilities(self) -> TerminalCapabilities {
        match self {
            Self::CloudApi => TerminalCapabilities {
                remote_checkout: true,
                reader_management: true,
                asynchronous_result: true,
                requires_companion_app: false,
            },
            Self::MobileReaderSdk => TerminalCapabilities {
                remote_checkout: false,
                reader_management: true,
                asynchronous_result: true,
                requires_companion_app: true,
            },
            Self::PaymentSwitch => TerminalCapabilities {
                remote_checkout: false,
                reader_management: false,
                asynchronous_result: true,
                requires_companion_app: true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solo_cloud_api_does_not_require_companion_app() {
        let capabilities = IntegrationPath::CloudApi.capabilities();
        assert!(capabilities.remote_checkout);
        assert!(capabilities.reader_management);
        assert!(capabilities.asynchronous_result);
        assert!(!capabilities.requires_companion_app);
    }

    #[test]
    fn mobile_reader_paths_require_companion_app() {
        assert!(IntegrationPath::MobileReaderSdk.capabilities().requires_companion_app);
        assert!(IntegrationPath::PaymentSwitch.capabilities().requires_companion_app);
    }
}
