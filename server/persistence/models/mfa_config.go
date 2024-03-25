package models

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gobuffalo/validate/v3/validators"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/validate/v3"
	"github.com/gofrs/uuid"
)

// MfaConfig is used by pop to map your mfa_configs database table to your go code.
type MfaConfig struct {
	ID                     uuid.UUID                            `json:"id" db:"id"`
	Config                 *Config                              `json:"config" belongs_to:"configs"`
	ConfigID               uuid.UUID                            `json:"config_id" db:"config_id"`
	Timeout                int                                  `json:"timeout" db:"timeout"`
	CreatedAt              time.Time                            `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time                            `json:"updated_at" db:"updated_at"`
	UserVerification       protocol.UserVerificationRequirement `json:"user_verification" db:"user_verification"`
	Attachment             protocol.AuthenticatorAttachment     `json:"attachment" db:"attachment"`
	AttestationPreference  protocol.ConveyancePreference        `json:"attestation_preference" db:"attestation_preference"`
	ResidentKeyRequirement protocol.ResidentKeyRequirement      `json:"resident_key_requirement" db:"resident_key_requirement"`
}

// Validate gets run every time you call a "pop.Validate*" (pop.ValidateAndSave, pop.ValidateAndCreate, pop.ValidateAndUpdate) method.
// This method is not required and may be deleted.
func (mfa *MfaConfig) Validate(_ *pop.Connection) (*validate.Errors, error) {
	return validate.Validate(
		&validators.UUIDIsPresent{Name: "ID", Field: mfa.ID},
		&validators.IntIsPresent{Name: "Timeout", Field: mfa.Timeout},
		&validators.StringIsPresent{Name: "UserVerification", Field: string(mfa.UserVerification)},
		&validators.StringIsPresent{Name: "Attachment", Field: string(mfa.Attachment)},
		&validators.StringIsPresent{Name: "AttestationPreference", Field: string(mfa.AttestationPreference)},
		&validators.StringIsPresent{Name: "ResidentKeyRequirement", Field: string(mfa.ResidentKeyRequirement)},
		&validators.TimeIsPresent{Name: "UpdatedAt", Field: mfa.UpdatedAt},
		&validators.TimeIsPresent{Name: "CreatedAt", Field: mfa.CreatedAt},
	), nil
}
