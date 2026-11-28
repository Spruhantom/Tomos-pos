use url::Url;

use crate::{Result, SumUpError};

/// Runtime configuration. Secrets are supplied by the deployment environment,
/// never committed to source control or returned from API responses.
#[derive(Clone)]
pub struct SumUpConfig {
    pub api_key: String,
    pub affiliate_key: String,
    pub merchant_code: String,
    pub api_base_url: Url,
}

impl std::fmt::Debug for SumUpConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SumUpConfig")
            .field("api_key", &"[REDACTED]")
            .field("affiliate_key", &"[REDACTED]")
            .field("merchant_code", &self.merchant_code)
            .field("api_base_url", &self.api_base_url)
            .finish()
    }
}

impl SumUpConfig {
    pub fn new(
        api_key: impl Into<String>,
        affiliate_key: impl Into<String>,
        merchant_code: impl Into<String>,
    ) -> Result<Self> {
        let api_key = api_key.into();
        let affiliate_key = affiliate_key.into();
        let merchant_code = merchant_code.into();

        if api_key.trim().is_empty()
            || affiliate_key.trim().is_empty()
            || merchant_code.trim().is_empty()
        {
            return Err(SumUpError::InvalidConfiguration(
                "API key, affiliate key and merchant code are required".into(),
            ));
        }

        Ok(Self {
            api_key,
            affiliate_key,
            merchant_code,
            api_base_url: Url::parse("https://api.sumup.com")
                .map_err(|error| SumUpError::InvalidConfiguration(error.to_string()))?,
        })
    }
}
