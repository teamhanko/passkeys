package models

import (
	"time"

	"github.com/gobuffalo/validate/v3/validators"

	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/validate/v3"
	"github.com/gofrs/uuid"
)

// WebauthnUser is used by pop to map your webauthn_users database table to your go code.
type WebauthnUser struct {
	ID          uuid.UUID `json:"id" db:"id"`
	UserID      string    `json:"user_id" db:"user_id"`
	Name        string    `json:"name" db:"name"`
	Icon        string    `json:"icon" db:"icon"`
	DisplayName string    `json:"display_name" db:"display_name"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
	Tenant      *Tenant   `json:"tenant" belongs_to:"tenant"`
	TenantID    uuid.UUID `json:"tenant_id" db:"tenant_id"`

	WebauthnCredentials WebauthnCredentials `json:"webauthn_credentials,omitempty" has_many:"webauthn_credentials"`
	Transactions        Transactions        `json:"transactions,omitempty" has_many:"transactions"`
}

type WebauthnUsers []WebauthnUser

func (webauthnUser *WebauthnUser) WebAuthnID() []byte {
	return []byte(webauthnUser.UserID)
}

func (webauthnUser *WebauthnUser) WebAuthnName() string {
	return webauthnUser.Name
}

func (webauthnUser *WebauthnUser) WebAuthnDisplayName() string {
	return webauthnUser.DisplayName
}

func (webauthnUser *WebauthnUser) WebAuthnIcon() string {
	return webauthnUser.Icon
}

// Validate gets run every time you call a "pop.Validate*" (pop.ValidateAndSave, pop.ValidateAndCreate, pop.ValidateAndUpdate) method.
// This method is not required and may be deleted.
func (webauthnUser *WebauthnUser) Validate(tx *pop.Connection) (*validate.Errors, error) {
	return validate.Validate(
		&validators.UUIDIsPresent{Name: "ID", Field: webauthnUser.ID},
		&validators.StringIsPresent{Name: "UserID", Field: webauthnUser.UserID},
		&validators.StringIsPresent{Name: "Name", Field: webauthnUser.Name},
		&validators.StringIsPresent{Name: "DisplayName", Field: webauthnUser.DisplayName},
		&validators.TimeIsPresent{Name: "UpdatedAt", Field: webauthnUser.UpdatedAt},
		&validators.TimeIsPresent{Name: "CreatedAt", Field: webauthnUser.CreatedAt},
	), nil
}
