package handler

import (
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gobuffalo/pop/v6"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/api/dto/response"
	"github.com/teamhanko/passkey-server/api/helper"
	"github.com/teamhanko/passkey-server/api/services"
	auditlog "github.com/teamhanko/passkey-server/audit_log"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
)

type mfaLoginHandler struct {
	*webauthnHandler
}

func NewMfaLoginHandler(persister persistence.Persister) WebauthnHandler {
	webauthnHandler := newWebAuthnHandler(persister, true)

	return &mfaLoginHandler{
		webauthnHandler,
	}
}

func (lh *mfaLoginHandler) Init(ctx echo.Context) error {
	h, err := helper.GetMfaHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	dto, err := BindAndValidateRequest[request.InitMfaLoginDto](ctx)
	if err != nil {
		return err
	}

	return lh.persister.GetConnection().Transaction(func(tx *pop.Connection) error {
		userPersister := lh.persister.GetWebauthnUserPersister(tx)
		sessionPersister := lh.persister.GetWebauthnSessionDataPersister(tx)
		credentialPersister := lh.persister.GetWebauthnCredentialPersister(tx)

		service := services.NewLoginService(services.WebauthnServiceCreateParams{
			Ctx:                 ctx,
			Tenant:              *h.Tenant,
			WebauthnClient:      *h.WebauthnClient,
			UserId:              &dto.UserId,
			UserPersister:       userPersister,
			SessionPersister:    sessionPersister,
			CredentialPersister: credentialPersister,
			UseMFA:              true,
		})

		credentialAssertion, err := service.Initialize()
		err = lh.handleError(h.AuditLog, models.AuditLogMfaAuthenticationInitFailed, tx, ctx, &dto.UserId, nil, err)
		if err != nil {
			return err
		}

		auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogMfaAuthenticationInitSucceeded, &dto.UserId, nil, nil)
		if auditErr != nil {
			ctx.Logger().Error(auditErr)
			return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
		}

		return ctx.JSON(http.StatusOK, credentialAssertion)
	})
}

func (lh *mfaLoginHandler) Finish(ctx echo.Context) error {
	parsedRequest, err := protocol.ParseCredentialRequestResponse(ctx.Request())
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to finish login").SetInternal(err)
	}

	h, err := helper.GetMfaHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return lh.persister.Transaction(func(tx *pop.Connection) error {
		userPersister := lh.persister.GetWebauthnUserPersister(tx)
		sessionPersister := lh.persister.GetWebauthnSessionDataPersister(tx)
		credentialPersister := lh.persister.GetWebauthnCredentialPersister(tx)

		service := services.NewLoginService(services.WebauthnServiceCreateParams{
			Ctx:                 ctx,
			Tenant:              *h.Tenant,
			WebauthnClient:      *h.WebauthnClient,
			UserPersister:       userPersister,
			SessionPersister:    sessionPersister,
			CredentialPersister: credentialPersister,
			Generator:           h.Generator,
			UseMFA:              true,
		})

		token, userId, err := service.Finalize(parsedRequest)
		err = lh.handleError(h.AuditLog, models.AuditLogMfaAuthenticationFinalFailed, tx, ctx, &userId, nil, err)
		if err != nil {
			return err
		}

		auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogMfaAuthenticationFinalSucceeded, &userId, nil, nil)
		if auditErr != nil {
			ctx.Logger().Error(auditErr)
			return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
		}

		return ctx.JSON(http.StatusOK, &response.TokenDto{Token: token})
	})
}
