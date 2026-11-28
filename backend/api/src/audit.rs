use serde_json::Value;
use sqlx::{Postgres, Transaction};

use crate::auth::AuthContext;

/// Supported audit event names are defined by the server, never by clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditEventType {
    BusinessCreated,
    BusinessUpdated,
    LocationCreated,
    LocationUpdated,
    ProductCreated,
    TillOpened,
    TillClosed,
    CashMovementRecorded,
    SaleCreated,
    CardPaymentInitiated,
    StaffInvited,
    StaffInvitationAccepted,
    StaffInvitationRevoked,
    StaffDeactivated,
    StaffRoleChanged,
    RoleCreated,
    RolePermissionsChanged,
}

impl AuditEventType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BusinessCreated => "business.created",
            Self::BusinessUpdated => "business.updated",
            Self::LocationCreated => "location.created",
            Self::LocationUpdated => "location.updated",
            Self::ProductCreated => "product.created",
            Self::TillOpened => "till.opened",
            Self::TillClosed => "till.closed",
            Self::CashMovementRecorded => "till.cash_movement_recorded",
            Self::SaleCreated => "sale.created",
            Self::CardPaymentInitiated => "payment.card_initiated",
            Self::StaffInvited => "staff.invited",
            Self::StaffInvitationAccepted => "staff.invitation_accepted",
            Self::StaffInvitationRevoked => "staff.invitation_revoked",
            Self::StaffDeactivated => "staff.deactivated",
            Self::StaffRoleChanged => "staff.role_changed",
            Self::RoleCreated => "role.created",
            Self::RolePermissionsChanged => "role.permissions_changed",
        }
    }
}

/// Entity categories are server-defined, never accepted as free-form input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditEntityType {
    Business,
    Location,
    Product,
    TillSession,
    CashMovement,
    Sale,
    Tender,
    Invitation,
    Membership,
    Role,
}

impl AuditEntityType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Business => "business",
            Self::Location => "business_location",
            Self::Product => "product",
            Self::TillSession => "till_session",
            Self::CashMovement => "till_cash_movement",
            Self::Sale => "sale",
            Self::Tender => "payment_tender",
            Self::Invitation => "staff_invitation",
            Self::Membership => "membership",
            Self::Role => "role",
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
        assert_eq!(AuditEventType::BusinessUpdated.as_str(), "business.updated");
        assert_eq!(AuditEventType::LocationCreated.as_str(), "location.created");
        assert_eq!(AuditEventType::LocationUpdated.as_str(), "location.updated");
        assert_eq!(AuditEntityType::Location.as_str(), "business_location");
        assert_eq!(AuditEventType::ProductCreated.as_str(), "product.created");
        assert_eq!(AuditEventType::SaleCreated.as_str(), "sale.created");
        assert_eq!(AuditEntityType::Sale.as_str(), "sale");
        assert_eq!(AuditEntityType::Tender.as_str(), "payment_tender");
        assert_eq!(AuditEntityType::Business.as_str(), "business");
        assert_eq!(AuditEventType::StaffInvited.as_str(), "staff.invited");
        assert_eq!(AuditEntityType::Invitation.as_str(), "staff_invitation");
        assert_eq!(
            AuditEventType::StaffDeactivated.as_str(),
            "staff.deactivated"
        );
        assert_eq!(
            AuditEventType::StaffRoleChanged.as_str(),
            "staff.role_changed"
        );
        assert_eq!(AuditEntityType::Membership.as_str(), "membership");
        assert_eq!(AuditEventType::RoleCreated.as_str(), "role.created");
        assert_eq!(
            AuditEventType::RolePermissionsChanged.as_str(),
            "role.permissions_changed"
        );
        assert_eq!(AuditEntityType::Role.as_str(), "role");
    }
}
