use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Result, SumUpError};

/// Amounts are expressed in integer minor units (for example, GBP pence).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Money {
    pub currency: String,
    pub minor_unit: u8,
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckoutRequest {
    pub reader_id: String,
    pub client_transaction_id: String,
    pub amount: Money,
    /// Publicly reachable HTTPS endpoint configured by the POS deployment.
    pub return_url: String,
}

impl CheckoutRequest {
    pub fn validate(&self) -> Result<()> {
        if self.reader_id.trim().is_empty() {
            return Err(SumUpError::InvalidRequest("reader_id is required".into()));
        }
        if self.client_transaction_id.trim().is_empty() {
            return Err(SumUpError::InvalidRequest(
                "client_transaction_id is required for idempotent correlation".into(),
            ));
        }
        if self.amount.value == 0 {
            return Err(SumUpError::InvalidRequest(
                "amount must be greater than zero".into(),
            ));
        }
        if self.amount.currency.len() != 3
            || !self
                .amount
                .currency
                .bytes()
                .all(|byte| byte.is_ascii_uppercase())
        {
            return Err(SumUpError::InvalidRequest(
                "currency must be a three-letter uppercase ISO 4217 code".into(),
            ));
        }
        let callback = url::Url::parse(&self.return_url)
            .map_err(|_| SumUpError::InvalidRequest("return_url must be a valid HTTPS URL".into()))?;
        if callback.scheme() != "https" {
            return Err(SumUpError::InvalidRequest(
                "return_url must use HTTPS".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn to_api_payload(&self, affiliate_key: &str) -> Value {
        serde_json::json!({
            "total_amount": {
                "currency": self.amount.currency,
                "minor_unit": self.amount.minor_unit,
                "value": self.amount.value
            },
            "client_transaction_id": self.client_transaction_id,
            "return_url": self.return_url,
            "affiliate_key": affiliate_key,
            "payment_type": "card"
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reader {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(flatten)]
    pub additional: std::collections::HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaderStatus {
    #[serde(flatten)]
    pub fields: std::collections::HashMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> CheckoutRequest {
        CheckoutRequest {
            reader_id: "reader-1".into(),
            client_transaction_id: "sale-unique-123".into(),
            amount: Money {
                currency: "GBP".into(),
                minor_unit: 2,
                value: 1250,
            },
            return_url: "https://pos.example.test/api/v1/payments/sumup/webhook".into(),
        }
    }

    #[test]
    fn accepts_valid_gbp_minor_units_and_https_callback() {
        assert!(valid_request().validate().is_ok());
    }

    #[test]
    fn rejects_http_callback() {
        let mut request = valid_request();
        request.return_url = "http://localhost/webhook".into();
        assert!(request.validate().is_err());
    }

    #[test]
    fn rejects_zero_amount() {
        let mut request = valid_request();
        request.amount.value = 0;
        assert!(request.validate().is_err());
    }
}
