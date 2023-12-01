package services

import (
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/intern"
	"github.com/teamhanko/passkey-server/crypto/jwt"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
	"net/http"
	"time"
)

type WebauthnService struct {
	*BaseService

	webauthnClient webauthn.WebAuthn
	generator      jwt.Generator

	userPersister        persisters.WebauthnUserPersister
	sessionDataPersister persisters.WebauthnSessionDataPersister
}

type WebauthnServiceCreateParams struct {
	Ctx            echo.Context
	Tenant         models.Tenant
	WebauthnClient webauthn.WebAuthn
	Generator      jwt.Generator

	UserPersister       persisters.WebauthnUserPersister
	SessionPersister    persisters.WebauthnSessionDataPersister
	CredentialPersister persisters.WebauthnCredentialPersister
}

func (ws *WebauthnService) getSessionByChallenge(challenge string, operation models.Operation) (*webauthn.SessionData, *models.WebauthnSessionData, error) {
	sessionData, err := ws.sessionDataPersister.GetByChallenge(challenge, ws.tenant.ID)
	if err != nil {
		ws.logger.Error(err)
		return nil, nil, err
	}

	if sessionData == nil || sessionData.Operation != operation {
		return nil, nil, echo.NewHTTPError(http.StatusBadRequest, "received challenge does not match with any stored one")
	}

	return intern.WebauthnSessionDataFromModel(sessionData), sessionData, nil
}

func (ws *WebauthnService) convertUserHandle(userHandle []byte) string {
	userId := string(userHandle)
	userUuid, err := uuid.FromBytes(userHandle)
	if err == nil {
		ws.logger.Error(err)
		userId = userUuid.String()
	}

	return userId
}

func (ws *WebauthnService) getWebauthnUserByUserHandle(userHandle string) (*intern.WebauthnUser, error) {
	user, err := ws.userPersister.GetByUserId(userHandle, ws.tenant.ID)
	if err != nil {
		ws.logger.Error(err)
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	return intern.NewWebauthnUser(*user), nil
}

func (ws *WebauthnService) createUserCredentialToken(userId string, credentialId string) (string, error) {
	token, err := ws.generator.Generate(userId, credentialId)
	if err != nil {
		ws.logger.Error(err)
		return "", fmt.Errorf("failed to generate jwt: %w", err)
	}

	return token, nil
}

func (ws *WebauthnService) updateCredentialForUser(webauthnUser *intern.WebauthnUser, credentialId string, flags protocol.AuthenticatorFlags) error {
	dbCredential := webauthnUser.FindCredentialById(credentialId)
	if dbCredential != nil {
		now := time.Now().UTC()

		dbCredential.BackupState = flags.HasBackupState()
		dbCredential.BackupEligible = flags.HasBackupEligible()
		dbCredential.LastUsedAt = &now
		err := ws.credentialPersister.Update(dbCredential)
		if err != nil {
			ws.logger.Error(err)
			return err
		}
	}

	return nil
}
