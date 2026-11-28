use reqwest::{Client, Method, RequestBuilder, Response};
use serde_json::Value;

use crate::{
    models::{CheckoutRequest, Reader, ReaderStatus},
    Result, SumUpConfig, SumUpError,
};

/// Thin, typed client for SumUp's official Solo Cloud API.
#[derive(Clone)]
pub struct SumUpClient {
    http: Client,
    config: SumUpConfig,
}

impl SumUpClient {
    pub fn new(config: SumUpConfig) -> Result<Self> {
        let http = Client::builder()
            .user_agent(concat!("TomOS-POS/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { http, config })
    }

    fn endpoint(&self, path: &str) -> String {
        format!(
            "{}/v0.1/merchants/{}/{}",
            self.config.api_base_url.as_str().trim_end_matches('/'),
            self.config.merchant_code,
            path.trim_start_matches('/')
        )
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.http
            .request(method, self.endpoint(path))
            .bearer_auth(&self.config.api_key)
            .header(reqwest::header::ACCEPT, "application/json")
    }

    async fn decode(response: Response) -> Result<Value> {
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(SumUpError::Api {
                status: status.as_u16(),
                body: body.chars().take(2_000).collect(),
            });
        }
        if body.is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_str(&body)?)
    }

    /// Pair a Solo reader using the short-lived code displayed on the device.
    /// SumUp pairing codes expire after five minutes.
    pub async fn pair_reader(&self, pairing_code: &str, name: Option<&str>) -> Result<Reader> {
        if pairing_code.trim().is_empty() {
            return Err(SumUpError::InvalidRequest("pairing_code is required".into()));
        }
        let mut payload = serde_json::json!({ "pairing_code": pairing_code });
        if let Some(name) = name.filter(|value| !value.trim().is_empty()) {
            payload["name"] = Value::String(name.to_owned());
        }
        let response = self
            .request(Method::POST, "readers")
            .json(&payload)
            .send()
            .await?;
        Ok(serde_json::from_value(Self::decode(response).await?)?)
    }

    pub async fn list_readers(&self) -> Result<Value> {
        let response = self.request(Method::GET, "readers").send().await?;
        Self::decode(response).await
    }

    pub async fn reader_status(&self, reader_id: &str) -> Result<ReaderStatus> {
        let response = self
            .request(Method::GET, &format!("readers/{reader_id}/status"))
            .send()
            .await?;
        Ok(serde_json::from_value(Self::decode(response).await?)?)
    }

    /// Starts an asynchronous checkout. The response is acceptance only;
    /// the caller must keep the sale unpaid until the final webhook is verified.
    pub async fn create_checkout(&self, checkout: &CheckoutRequest) -> Result<Value> {
        checkout.validate()?;
        let response = self
            .request(
                Method::POST,
                &format!("readers/{}/checkout", checkout.reader_id),
            )
            .json(&checkout.to_api_payload(&self.config.affiliate_key))
            .send()
            .await?;
        Self::decode(response).await
    }

    /// Requests termination; SumUp performs this asynchronously on the reader.
    pub async fn terminate_checkout(&self, reader_id: &str) -> Result<Value> {
        if reader_id.trim().is_empty() {
            return Err(SumUpError::InvalidRequest("reader_id is required".into()));
        }
        let response = self
            .request(Method::POST, &format!("readers/{reader_id}/terminate"))
            .json(&serde_json::json!({}))
            .send()
            .await?;
        Self::decode(response).await
    }
}
