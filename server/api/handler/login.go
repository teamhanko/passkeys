package handler

import (
	"encoding/base64"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/intern"
	"github.com/teamhanko/passkey-server/api/dto/response"
	"github.com/teamhanko/passkey-server/api/helper"
	auditlog "github.com/teamhanko/passkey-server/audit_log"
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

func NewLoginHandler(persister persistence.Persister) WebauthnHandler {
	webauthnHandler := newWebAuthnHandler(persister)

	return &loginHandler{
		webauthnHandler,
	}
}

func (lh *loginHandler) Init(ctx echo.Context) error {
	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return lh.persister.GetConnection().Transaction(func(tx *pop.Connection) error {
		options, sessionData, err := h.Webauthn.BeginDiscoverableLogin(
			webauthn.WithUserVerification(h.Config.WebauthnConfig.UserVerification),
		)
		if err != nil {
			auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnAuthenticationInitFailed, nil, nil, err)
			if auditErr != nil {
				ctx.Logger().Error(auditErr)
				return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
			}

			ctx.Logger().Error(err)
			return echo.NewHTTPError(
				http.StatusBadRequest,
				fmt.Errorf("failed to create webauthn assertion options for discoverable login: %w", err),
			)
		}

		err = lh.persister.GetWebauthnSessionDataPersister(tx).Create(*intern.WebauthnSessionDataToModel(sessionData, h.Tenant.ID, models.WebauthnOperationAuthentication))
		if err != nil {
			auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnAuthenticationInitFailed, nil, nil, err)
			if auditErr != nil {
				ctx.Logger().Error(auditErr)
				return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
			}

			ctx.Logger().Error(err)
			return fmt.Errorf("failed to store webauthn assertion session data: %w", err)
		}

		// Remove all transports, because of a bug in android and windows where the internal authenticator gets triggered,
		// when the transports array contains the type 'internal' although the credential is not available on the device.
		for i := range options.Response.AllowedCredentials {
			options.Response.AllowedCredentials[i].Transport = nil
		}

		auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnAuthenticationInitSucceeded, nil, nil, nil)
		if auditErr != nil {
			ctx.Logger().Error(auditErr)
			return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
		}

		return ctx.JSON(http.StatusOK, options)
	})
}

func (lh *loginHandler) Finish(ctx echo.Context) error {
	parsedRequest, err := protocol.ParseCredentialRequestResponse(ctx.Request())
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return lh.persister.Transaction(func(tx *pop.Connection) error {
		sessionDataPersister := lh.persister.GetWebauthnSessionDataPersister(tx)
		webauthnUserPersister := lh.persister.GetWebauthnUserPersister(tx)
		credentialPersister := lh.persister.GetWebauthnCredentialPersister(tx)

		// backward compatibility
		userHandle := lh.convertUserHandle(parsedRequest.Response.UserHandle)
		parsedRequest.Response.UserHandle = []byte(userHandle)

		sessionData, err := lh.getSessionDataByChallenge(parsedRequest.Response.CollectedClientData.Challenge, sessionDataPersister, h.Tenant.ID)
		if err != nil {
			auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnAuthenticationFinalFailed, nil, nil, err)
			if auditErr != nil {
				ctx.Logger().Error(auditErr)
				return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
			}

			ctx.Logger().Error(err)
			return echo.NewHTTPError(http.StatusUnauthorized, "failed to get session data").SetInternal(err)
		}
		sessionDataModel := intern.WebauthnSessionDataFromModel(sessionData)

		webauthnUser, err := lh.getWebauthnUserByUserHandle(userHandle, h.Tenant.ID, webauthnUserPersister)
		if err != nil {
			auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnAuthenticationFinalFailed, &webauthnUser.UserId, nil, err)
			if auditErr != nil {
				ctx.Logger().Error(auditErr)
				return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
			}

			ctx.Logger().Error(err)
			return echo.NewHTTPError(http.StatusUnauthorized, "failed to get user handle")
		}

		credential, err := h.Webauthn.ValidateDiscoverableLogin(func(rawID, userHandle []byte) (user webauthn.User, err error) {
			return webauthnUser, nil
		}, *sessionDataModel, parsedRequest)

		if err != nil {
			auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnAuthenticationFinalFailed, &webauthnUser.UserId, nil, err)
			if auditErr != nil {
				ctx.Logger().Error(auditErr)
				return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
			}

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
				auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnAuthenticationFinalFailed, &webauthnUser.UserId, nil, err)
				if auditErr != nil {
					ctx.Logger().Error(auditErr)
					return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
				}

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

		auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnAuthenticationFinalSucceeded, &webauthnUser.UserId, nil, nil)
		if auditErr != nil {
			ctx.Logger().Error(auditErr)
			return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
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

func (lh *loginHandler) getWebauthnUserByUserHandle(userHandle string, tenantId uuid.UUID, persister persisters.WebauthnUserPersister) (*intern.WebauthnUser, error) {
	user, err := persister.GetByUserId(userHandle, tenantId)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	return intern.NewWebauthnUser(*user), nil
}
