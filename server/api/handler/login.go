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

func NewLoginHandler(persister persistence.Persister) (WebauthnHandler, error) {
	webauthnHandler, err := newWebAuthnHandler(persister)
	if err != nil {
		return nil, err
	}

	return &loginHandler{
		webauthnHandler,
	}, nil
}

func (lh *loginHandler) Init(ctx echo.Context) error {
	h, err := GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	options, sessionData, err := h.webauthn.BeginDiscoverableLogin(
		webauthn.WithUserVerification(h.config.WebauthnConfig.UserVerification),
	)
	if err != nil {
		ctx.Logger().Error(err)
		return fmt.Errorf("failed to create webauthn assertion options for discoverable login: %w", err)
	}

	err = lh.persister.GetWebauthnSessionDataPersister(nil).Create(*intern.WebauthnSessionDataToModel(sessionData, h.tenant.ID, models.WebauthnOperationAuthentication))
	if err != nil {
		ctx.Logger().Error(err)
		return fmt.Errorf("failed to store webauthn assertion session data: %w", err)
	}

	// Remove all transports, because of a bug in android and windows where the internal authenticator gets triggered,
	// when the transports array contains the type 'internal' although the credential is not available on the device.
	for i := range options.Response.AllowedCredentials {
		options.Response.AllowedCredentials[i].Transport = nil
	}

	return ctx.JSON(http.StatusOK, options)
}

func (lh *loginHandler) Finish(ctx echo.Context) error {
	parsedRequest, err := protocol.ParseCredentialRequestResponse(ctx.Request())
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	h, err := GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return lh.persister.Transaction(func(tx *pop.Connection) error {
		sessionDataPersister := lh.persister.GetWebauthnSessionDataPersister(tx)
		webauthnUserPersister := lh.persister.GetWebauthnUserPersister(tx)
		credentialPersister := lh.persister.GetWebauthnCredentialPersister(tx)

		sessionData, err := lh.getSessionDataByChallenge(parsedRequest.Response.CollectedClientData.Challenge, sessionDataPersister, h.tenant.ID)
		if err != nil {
			ctx.Logger().Error(err)
			return echo.NewHTTPError(http.StatusUnauthorized, "failed to get session data").SetInternal(err)
		}
		sessionDataModel := intern.WebauthnSessionDataFromModel(sessionData)

		webauthnUser, err := lh.getWebauthnUserByUserHandle(parsedRequest.Response.UserHandle, h.tenant.ID, webauthnUserPersister)
		if err != nil {
			ctx.Logger().Error(err)
			return echo.NewHTTPError(http.StatusUnauthorized, "failed to get user handle").SetInternal(err)
		}

		credential, err := h.webauthn.ValidateDiscoverableLogin(func(rawID, userHandle []byte) (user webauthn.User, err error) {
			return webauthnUser, nil
		}, *sessionDataModel, parsedRequest)

		if err != nil {
			ctx.Logger().Error(err)
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
				ctx.Logger().Error(err)
				return fmt.Errorf("failed to update webauthn credential: %w", err)
			}
		}

		err = sessionDataPersister.Delete(*sessionData)
		if err != nil {
			ctx.Logger().Error(err)
			return fmt.Errorf("failed to delete assertion session data: %w", err)
		}

		generator := ctx.Get("jwt_generator").(jwt.Generator)
		token, err := generator.Generate(webauthnUser.UserId, base64.RawURLEncoding.EncodeToString(credential.ID))
		if err != nil {
			ctx.Logger().Error(err)
			return fmt.Errorf("failed to generate jwt: %w", err)
		}

		return ctx.JSON(http.StatusOK, &response.TokenDto{Token: token})
	})
}

func (lh *loginHandler) getSessionDataByChallenge(challenge string, persister persisters.WebauthnSessionDataPersister, tenantId uuid.UUID) (*models.WebauthnSessionData, error) {
	sessionData, err := persister.GetByChallenge(challenge, tenantId)
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

func (lh *loginHandler) getWebauthnUserByUserHandle(userHandle []byte, tenantId uuid.UUID, persister persisters.WebauthnUserPersister) (*intern.WebauthnUser, error) {
	user, err := persister.GetByUserId(string(userHandle), tenantId)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if user == nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized).SetInternal(errors.New("user not found"))
	}

	return intern.NewWebauthnUser(*user), nil
}
