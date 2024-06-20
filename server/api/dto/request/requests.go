package request

import (
	"encoding/json"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
	"strings"
	"time"
)

type CredentialRequests interface {
	ListCredentialsDto | DeleteCredentialsDto | UpdateCredentialsDto
}

type TenantDto struct {
	TenantId string `param:"tenant_id" validate:"required,uuid4"`
}

type ListCredentialsDto struct {
	UserId string `query:"user_id" validate:"required"`
}

type DeleteCredentialsDto struct {
	CredentialId string `param:"credential_id" validate:"required"`
}

type UpdateCredentialsDto struct {
	CredentialId string `param:"credential_id" validate:"required"`
	Name         string `json:"name" validate:"required"`
}

type WebauthnRequests interface {
	InitRegistrationDto | InitTransactionDto | InitLoginDto | InitMfaLoginDto
}

type InitRegistrationDto struct {
	UserId      string  `json:"user_id" validate:"required"`
	Username    string  `json:"username" validate:"required,max=128"`
	DisplayName *string `json:"display_name" validate:"omitempty,max=128"`
	Icon        *string `json:"icon" validate:"omitempty,url"`
}

func (initRegistration *InitRegistrationDto) ToModel() *models.WebauthnUser {
	icon := ""
	if initRegistration.Icon != nil {
		icon = *initRegistration.Icon
	}

	displayName := initRegistration.Username
	if initRegistration.DisplayName != nil && len(strings.TrimSpace(*initRegistration.DisplayName)) > 0 {
		displayName = *initRegistration.DisplayName
	}

	webauthnId, _ := uuid.NewV4()

	now := time.Now()

	return &models.WebauthnUser{
		ID:          webauthnId,
		UserID:      initRegistration.UserId,
		Name:        initRegistration.Username,
		Icon:        icon,
		DisplayName: displayName,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

type InitTransactionDto struct {
	UserId          string      `json:"user_id" validate:"required"`
	TransactionId   string      `json:"transaction_id" validate:"required,max=128"`
	TransactionData interface{} `json:"transaction_data" validate:"required"`
}

func (initTransaction *InitTransactionDto) ToModel() (*models.Transaction, error) {
	transactionUuid, _ := uuid.NewV4()

	byteArray, err := json.Marshal(initTransaction.TransactionData)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	return &models.Transaction{
		ID:         transactionUuid,
		Identifier: initTransaction.TransactionId,
		Data:       string(byteArray),

		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

type InitLoginDto struct {
	UserId *string `json:"user_id" validate:"omitempty,min=1"`
}

type InitMfaLoginDto struct {
	UserId string `json:"user_id" validate:"required,min=1"`
}
