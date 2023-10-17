package handler

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/intern"
	"github.com/teamhanko/passkey-server/api/dto/response"
	auditlog "github.com/teamhanko/passkey-server/audit_log"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/crypto/jwt"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
	"net/http"
	"time"
)

type loginHandler struct {
	*webauthnHandler
}

func NewLoginHandler(cfg *config.Config, persister persistence.Persister, logger auditlog.Logger, generator jwt.Generator) (WebauthnHandler, error) {
	webauthnHandler, err := newWebAuthnHandler(cfg, persister, logger, generator)
	if err != nil {
		return nil, err
	}

	return &loginHandler{
		webauthnHandler,
	}, nil
}

func (lh *loginHandler) Init(ctx echo.Context) error {
	options, sessionData, err := lh.webauthn.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.UserVerificationRequirement(lh.config.Webauthn.UserVerification)),
	)
	if err != nil {
		return fmt.Errorf("failed to create webauthn assertion options for discoverable login: %w", err)
	}

	err = lh.persister.GetWebauthnSessionDataPersister(nil).Create(*intern.WebauthnSessionDataToModel(sessionData, models.WebauthnOperationAuthentication))
	if err != nil {
		return fmt.Errorf("failed to store webauthn assertion session data: %w", err)
	}

	// Remove all transports, because of a bug in android and windows where the internal authenticator gets triggered,
	// when the transports array contains the type 'internal' although the credential is not available on the device.
	for i, _ := range options.Response.AllowedCredentials {
		options.Response.AllowedCredentials[i].Transport = nil
	}

	return ctx.JSON(http.StatusOK, options)
}

func (lh *loginHandler) Finish(ctx echo.Context) error {
	parsedRequest, err := protocol.ParseCredentialRequestResponse(ctx.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	return lh.persister.Transaction(func(tx *pop.Connection) error {
		sessionDataPersister := lh.persister.GetWebauthnSessionDataPersister(tx)
		webauthnUserPersister := lh.persister.GetWebauthnUserPersister(tx)
		credentialPersister := lh.persister.GetWebauthnCredentialPersister(tx)

		sessionData, err := lh.getSessionDataByChallenge(parsedRequest.Response.CollectedClientData.Challenge, sessionDataPersister)
		sessionDataModel := intern.WebauthnSessionDataFromModel(sessionData)

		webauthnUser, err := lh.getWebauthnUserByUserHandle(parsedRequest.Response.UserHandle, webauthnUserPersister)

		credential, err := lh.webauthn.ValidateDiscoverableLogin(func(rawID, userHandle []byte) (user webauthn.User, err error) {
			return webauthnUser, nil
		}, *sessionDataModel, parsedRequest)

		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "failed to validate assertion").SetInternal(err)
		}

		dbCred := webauthnUser.FindCredentialById(base64.RawURLEncoding.EncodeToString(credential.ID))
		if dbCred != nil {
			flags := parsedRequest.Response.AuthenticatorData.Flags
			now := time.Now().UTC()

			dbCred.BackupState = flags.HasBackupState()
			dbCred.BackupEligible = flags.HasBackupEligible()
			dbCred.LastUsedAt = &now
			err = credentialPersister.Update(dbCred)
			if err != nil {
				return fmt.Errorf("failed to update webauthn credential: %w", err)
			}
		}

		err = sessionDataPersister.Delete(*sessionData)
		if err != nil {
			return fmt.Errorf("failed to delete assertion session data: %w", err)
		}

		token, err := lh.jwtGenerator.Generate(webauthnUser.UserId, base64.RawURLEncoding.EncodeToString(credential.ID))
		if err != nil {
			return fmt.Errorf("failed to generate jwt: %w", err)
		}

		return ctx.JSON(http.StatusOK, &response.TokenDto{Token: token})
	})
}

func (lh *loginHandler) getSessionDataByChallenge(challenge string, persister persisters.WebauthnSessionDataPersister) (*models.WebauthnSessionData, error) {
	sessionData, err := persister.GetByChallenge(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to get webauthn assertion session data: %w", err)
	}

	if sessionData != nil && sessionData.Operation != models.WebauthnOperationAuthentication {
		sessionData = nil
	}

	if sessionData == nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "received challenge does not match with any stored one")
	}

	return sessionData, nil
}

func (lh *loginHandler) getWebauthnUserByUserHandle(userHandle []byte, persister persisters.WebauthnUserPersister) (*intern.WebauthnUser, error) {
	userId, err := uuid.FromBytes(userHandle)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "failed to parse userHandle as uuid").SetInternal(err)
	}

	user, err := persister.GetByUserId(userId)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if user == nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized).SetInternal(errors.New("user not found"))
	}

	return intern.NewWebauthnUser(*user), nil
}
