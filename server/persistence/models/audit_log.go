package models

import (
	"time"

	"github.com/gofrs/uuid"
)

type AuditLog struct {
	ID                uuid.UUID    `db:"id" json:"id"`
	Type              AuditLogType `db:"type" json:"type"`
	Error             *string      `db:"error" json:"error,omitempty"`
	MetaHttpRequestId string       `db:"meta_http_request_id" json:"meta_http_request_id"`
	MetaSourceIp      string       `db:"meta_source_ip" json:"meta_source_ip"`
	MetaUserAgent     string       `db:"meta_user_agent" json:"meta_user_agent"`
	ActorUserId       *string      `db:"actor_user_id" json:"actor_user_id,omitempty"`
	CreatedAt         time.Time    `db:"created_at" json:"created_at"`
	UpdatedAt         time.Time    `db:"updated_at" json:"updated_at"`
	Tenant            *Tenant      `json:"tenant" belongs_to:"tenants"`
	TenantID          uuid.UUID    `json:"tenant_id" db:"tenant_id"`
}

type AuditLogs []AuditLog

type AuditLogType string

var (
	AuditLogWebAuthnRegistrationInitSucceeded  AuditLogType = "webauthn_registration_init_succeeded"
	AuditLogWebAuthnRegistrationInitFailed     AuditLogType = "webauthn_registration_init_failed"
	AuditLogWebAuthnRegistrationFinalSucceeded AuditLogType = "webauthn_registration_final_succeeded"
	AuditLogWebAuthnRegistrationFinalFailed    AuditLogType = "webauthn_registration_final_failed"

	AuditLogWebAuthnAuthenticationInitSucceeded  AuditLogType = "webauthn_authentication_init_succeeded"
	AuditLogWebAuthnAuthenticationInitFailed     AuditLogType = "webauthn_authentication_init_failed"
	AuditLogWebAuthnAuthenticationFinalSucceeded AuditLogType = "webauthn_authentication_final_succeeded"
	AuditLogWebAuthnAuthenticationFinalFailed    AuditLogType = "webauthn_authentication_final_failed"

	AuditLogWebAuthnCredentialUpdated AuditLogType = "webauthn_credential_updated"
	AuditLogWebAuthnCredentialDeleted AuditLogType = "webauthn_credential_deleted"
)
