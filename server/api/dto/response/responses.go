package response

import (
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
	"time"
)

type CredentialDto struct {
	ID              string     `json:"id"`
	Name            *string    `json:"name,omitempty"`
	PublicKey       string     `json:"public_key"`
	AttestationType string     `json:"attestation_type"`
	AAGUID          uuid.UUID  `json:"aaguid"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	Transports      []string   `json:"transports"`
	BackupEligible  bool       `json:"backup_eligible"`
	BackupState     bool       `json:"backup_state"`
	IsMFA           bool       `json:"is_mfa"`
}

type CredentialDtoList []CredentialDto

type TokenDto struct {
	Token string `json:"token"`
}

func CredentialDtoFromModel(credential models.WebauthnCredential) CredentialDto {
	return CredentialDto{
		ID:              credential.ID,
		Name:            credential.Name,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          credential.AAGUID,
		LastUsedAt:      credential.LastUsedAt,
		CreatedAt:       credential.CreatedAt,
		Transports:      credential.Transports.GetNames(),
		BackupEligible:  credential.BackupEligible,
		BackupState:     credential.BackupState,
		IsMFA:           credential.IsMFA,
	}
}

type TransactionDto struct {
	ID         string `json:"id"`
	Identifier string `json:"identifier"`
	Data       string `json:"data"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func TransactionDtoFromModel(transaction models.Transaction) TransactionDto {
	return TransactionDto{
		ID:         transaction.ID.String(),
		Identifier: transaction.Identifier,
		Data:       transaction.Data,
		CreatedAt:  transaction.CreatedAt,
		UpdatedAt:  transaction.UpdatedAt,
	}
}
