use serde::Deserialize;

use crate::{Result, SumUpError};

pub const SOLO_TRANSACTION_UPDATED: &str = "solo.transaction.updated";

#[derive(Debug, Clone, Deserialize)]
pub struct SoloWebhookEvent {
    pub id: String,
    pub event_type: String,
    pub payload: SoloWebhookPayload,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SoloWebhookPayload {
    pub client_transaction_id: String,
    pub merchant_code: String,
    pub status: String,
    #[serde(default)]
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentOutcome {
    Successful,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied(PaymentOutcome),
    AlreadyApplied(PaymentOutcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptStatus {
    Pending,
    Successful,
    Failed,
}

/// A payment attempt is settled only by a final event matching both the
/// merchant and the unique client transaction ID used to create the checkout.
#[derive(Debug, Clone)]
pub struct PaymentAttempt {
    pub client_transaction_id: String,
    pub merchant_code: String,
    status: AttemptStatus,
    last_event_id: Option<String>,
}

impl PaymentAttempt {
    pub fn new(client_transaction_id: String, merchant_code: String) -> Result<Self> {
        if client_transaction_id.trim().is_empty() || merchant_code.trim().is_empty() {
            return Err(SumUpError::InvalidRequest(
                "merchant code and client transaction ID are required".into(),
            ));
        }
        Ok(Self {
            client_transaction_id,
            merchant_code,
            status: AttemptStatus::Pending,
            last_event_id: None,
        })
    }

    pub fn status(&self) -> AttemptStatus {
        self.status
    }

    /// Validates and applies a Solo callback. This does not claim cryptographic
    /// signature verification: the Cloud API callback contract documents no
    /// signature header. The HTTP receiver must additionally protect its
    /// callback URL with a high-entropy per-attempt bearer token and HTTPS.
    pub fn apply_webhook(&mut self, event: &SoloWebhookEvent) -> Result<ApplyOutcome> {
        if event.id.trim().is_empty() {
            return Err(SumUpError::InvalidRequest(
                "webhook event ID is required".into(),
            ));
        }
        if event.event_type != SOLO_TRANSACTION_UPDATED {
            return Err(SumUpError::InvalidRequest(
                "unsupported webhook event type".into(),
            ));
        }
        if event.payload.merchant_code != self.merchant_code {
            return Err(SumUpError::InvalidRequest(
                "webhook merchant does not match payment attempt".into(),
            ));
        }
        if event.payload.client_transaction_id != self.client_transaction_id {
            return Err(SumUpError::InvalidRequest(
                "webhook transaction does not match payment attempt".into(),
            ));
        }

        let outcome = match event.payload.status.as_str() {
            "successful" => PaymentOutcome::Successful,
            "failed" => PaymentOutcome::Failed,
            _ => {
                return Err(SumUpError::InvalidRequest(
                    "webhook status is not final or recognised".into(),
                ))
            }
        };

        let next_status = match outcome {
            PaymentOutcome::Successful => AttemptStatus::Successful,
            PaymentOutcome::Failed => AttemptStatus::Failed,
        };

        match self.status {
            AttemptStatus::Pending => {
                self.status = next_status;
                self.last_event_id = Some(event.id.clone());
                Ok(ApplyOutcome::Applied(outcome))
            }
            AttemptStatus::Successful if outcome == PaymentOutcome::Successful => {
                Ok(ApplyOutcome::AlreadyApplied(outcome))
            }
            AttemptStatus::Failed if outcome == PaymentOutcome::Failed => {
                Ok(ApplyOutcome::AlreadyApplied(outcome))
            }
            AttemptStatus::Successful | AttemptStatus::Failed => Err(SumUpError::InvalidRequest(
                "conflicting final payment event; reconciliation required".into(),
            )),
        }
    }

    pub fn last_event_id(&self) -> Option<&str> {
        self.last_event_id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt() -> PaymentAttempt {
        PaymentAttempt::new("sale-123".into(), "merchant-456".into()).unwrap()
    }

    fn event(status: &str) -> SoloWebhookEvent {
        SoloWebhookEvent {
            id: "event-789".into(),
            event_type: SOLO_TRANSACTION_UPDATED.into(),
            payload: SoloWebhookPayload {
                client_transaction_id: "sale-123".into(),
                merchant_code: "merchant-456".into(),
                status: status.into(),
                failure_reason: None,
            },
        }
    }

    #[test]
    fn successful_callback_confirms_matching_attempt() {
        let mut payment = attempt();
        assert_eq!(
            payment.apply_webhook(&event("successful")).unwrap(),
            ApplyOutcome::Applied(PaymentOutcome::Successful)
        );
        assert_eq!(payment.status(), AttemptStatus::Successful);
        assert_eq!(payment.last_event_id(), Some("event-789"));
    }

    #[test]
    fn failed_callback_never_confirms_payment() {
        let mut payment = attempt();
        assert_eq!(
            payment.apply_webhook(&event("failed")).unwrap(),
            ApplyOutcome::Applied(PaymentOutcome::Failed)
        );
        assert_eq!(payment.status(), AttemptStatus::Failed);
    }

    #[test]
    fn duplicate_final_callback_is_idempotent() {
        let mut payment = attempt();
        payment.apply_webhook(&event("successful")).unwrap();
        assert_eq!(
            payment.apply_webhook(&event("successful")).unwrap(),
            ApplyOutcome::AlreadyApplied(PaymentOutcome::Successful)
        );
    }

    #[test]
    fn conflicting_final_callback_requires_reconciliation() {
        let mut payment = attempt();
        payment.apply_webhook(&event("successful")).unwrap();
        assert!(payment.apply_webhook(&event("failed")).is_err());
        assert_eq!(payment.status(), AttemptStatus::Successful);
    }

    #[test]
    fn wrong_merchant_or_transaction_cannot_settle_attempt() {
        let mut payment = attempt();
        let mut wrong_merchant = event("successful");
        wrong_merchant.payload.merchant_code = "other-merchant".into();
        assert!(payment.apply_webhook(&wrong_merchant).is_err());

        let mut wrong_reference = event("successful");
        wrong_reference.payload.client_transaction_id = "another-sale".into();
        assert!(payment.apply_webhook(&wrong_reference).is_err());
        assert_eq!(payment.status(), AttemptStatus::Pending);
    }

    #[test]
    fn unknown_event_or_non_final_status_is_rejected() {
        let mut payment = attempt();
        let mut unknown_event = event("successful");
        unknown_event.event_type = "new.event.type".into();
        assert!(payment.apply_webhook(&unknown_event).is_err());

        assert!(payment.apply_webhook(&event("processing")).is_err());
        assert_eq!(payment.status(), AttemptStatus::Pending);
    }
}
