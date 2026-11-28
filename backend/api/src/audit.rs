use serde_json::Value;
use sqlx::{Postgres, Transaction};

use crate::auth::AuthContext;

/// Supported audit event names are defined by the server, never by clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditEventType {
    BusinessCreated,
    StaffInvited,
    StaffInvitationAccepted,
    SaleCreated,
    ProductCreated,
}

impl AuditEventType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BusinessCreated => "business.created",
            Self::StaffInvited => "staff.invited",
            Self::StaffInvitationAccepted => "staff.invitation_accepted",
            Self::SaleCreated => "sale.created",
            Self::ProductCreated => "catalogue.product_created",
        }
    }
}

/// Entity categories are server-defined, never accepted as free-form input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditEntityType {
    Business,
    Invitation,
    Membership,
    Sale,
    Product,
}

impl AuditEntityType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Business => "business",
            Self::Invitation => "staff_invitation",
            Self::Membership => "membership",
            Self::Sale => "sale",
            Self::Product => "product",
        }
    }
}

/// Append an audit event in the same tenant-scoped transaction as the
/// business mutation. A caller must commit or roll back both together.
pub async fn record_event(
    tx: &mut Transaction<'_, Postgres>,
    context: &AuthContext,
    event_type: AuditEventType,
    entity_type: AuditEntityType,
    entity_id: Option<uuid::Uuid>,
    event_data: Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events \
         (tenant_id, actor_user_id, event_type, entity_type, entity_id, event_data) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(context.tenant_id)
    .bind(context.user_id)
    .bind(event_type.as_str())
    .bind(entity_type.as_str())
    .bind(entity_id)
    .bind(event_data)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AuditEntityType, AuditEventType};

    #[test]
    fn audit_vocabulary_is_stable_and_server_defined() {
        assert_eq!(AuditEventType::BusinessCreated.as_str(), "business.created");
        assert_eq!(AuditEntityType::Business.as_str(), "business");
        assert_eq!(AuditEventType::StaffInvited.as_str(), "staff.invited");
        assert_eq!(AuditEntityType::Invitation.as_str(), "staff_invitation");
    }
}
