package models

import (
	"github.com/gobuffalo/validate/v3/validators"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/validate/v3"
	"github.com/gofrs/uuid"
)

// Transaction is used by pop to map your transactions database table to your go code.
type Transaction struct {
	ID         uuid.UUID `db:"id"`
	Identifier string    `db:"identifier"`
	Data       string    `db:"data"`
	Challenge  string    `db:"challenge"`

	WebauthnUserID uuid.UUID     `db:"webauthn_user_id"`
	WebauthnUser   *WebauthnUser `belongs_to:"webauthn_user"`

	TenantID uuid.UUID `db:"tenant_id"`
	Tenant   *Tenant   `belongs_to:"tenants"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

type Transactions []Transaction

// Validate gets run every time you call a "pop.Validate*" (pop.ValidateAndSave, pop.ValidateAndCreate, pop.ValidateAndUpdate) method.
// This method is not required and may be deleted.
func (transaction *Transaction) Validate(tx *pop.Connection) (*validate.Errors, error) {
	return validate.Validate(
		&validators.UUIDIsPresent{Name: "ID", Field: transaction.ID},
		&validators.UUIDIsPresent{Name: "WebauthnUserId", Field: transaction.WebauthnUserID},
		&validators.UUIDIsPresent{Name: "TenantId", Field: transaction.TenantID},
		&validators.StringLengthInRange{Name: "Challenge", Field: transaction.Challenge, Min: 16, Max: 255},
		&validators.StringIsPresent{Name: "Data", Field: transaction.Data},
		&validators.TimeIsPresent{Name: "UpdatedAt", Field: transaction.UpdatedAt},
		&validators.TimeIsPresent{Name: "CreatedAt", Field: transaction.CreatedAt},
	), nil
}
