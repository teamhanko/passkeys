package services

import (
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
)

type BaseService struct {
	logger echo.Logger
	tenant models.Tenant

	credentialPersister persisters.WebauthnCredentialPersister
}
