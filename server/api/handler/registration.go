package handler

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gobuffalo/pop/v6"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/api/dto/response"
	"github.com/teamhanko/passkey-server/api/helper"
	"github.com/teamhanko/passkey-server/api/services"
	"github.com/teamhanko/passkey-server/mapper"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
)

type registrationHandler struct {
	*webauthnHandler
	mapper.AuthenticatorMetadata
}

func NewRegistrationHandler(persister persistence.Persister, authenticatorMetadata mapper.AuthenticatorMetadata, useMfaClient bool) WebauthnHandler {
	webauthnHandler := newWebAuthnHandler(persister, useMfaClient)

	return &registrationHandler{
		webauthnHandler,
		authenticatorMetadata,
	}
}

func (r *registrationHandler) Init(ctx echo.Context) error {
	dto, err := BindAndValidateRequest[request.InitRegistrationDto](ctx)
	if err != nil {
		return err
	}

	webauthnUser := dto.ToModel()

	var h *helper.WebauthnContext
	var hErr error
	if r.UseMFAClient {
		h, hErr = helper.GetMfaHandlerContext(ctx)
	} else {
		h, hErr = helper.GetHandlerContext(ctx)
	}

	if hErr != nil {
		ctx.Logger().Error(err)
		return err
	}

	return r.persister.Transaction(func(tx *pop.Connection) error {
		userPersister := r.persister.GetWebauthnUserPersister(tx)
		sessionPersister := r.persister.GetWebauthnSessionDataPersister(tx)
		credentialPersister := r.persister.GetWebauthnCredentialPersister(tx)

		service := services.NewRegistrationService(services.WebauthnServiceCreateParams{
			Ctx:                 ctx,
			Tenant:              *h.Tenant,
			WebauthnClient:      *h.WebauthnClient,
			UserPersister:       userPersister,
			SessionPersister:    sessionPersister,
			CredentialPersister: credentialPersister,
			UseMFA:              r.UseMFAClient,
		})

		credentialCreation, userId, err := service.Initialize(webauthnUser)
		err = r.handleError(h.AuditLog, models.AuditLogWebAuthnRegistrationInitFailed, tx, ctx, &userId, nil, err)
		if err != nil {
			return err
		}

		auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnRegistrationInitSucceeded, &userId, nil, err)
		if auditErr != nil {
			ctx.Logger().Error(auditErr)
			return auditErr
		}

		return ctx.JSON(http.StatusOK, credentialCreation)
	})
}

func (r *registrationHandler) Finish(ctx echo.Context) error {
	parsedRequest, err := protocol.ParseCredentialCreationResponse(ctx.Request())
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to parse credential creation response").SetInternal(err)
	}

	var h *helper.WebauthnContext
	var hErr error
	if r.UseMFAClient {
		h, hErr = helper.GetMfaHandlerContext(ctx)
	} else {
		h, hErr = helper.GetHandlerContext(ctx)
	}

	if hErr != nil {
		ctx.Logger().Error(err)
		return err
	}

	return r.persister.Transaction(func(tx *pop.Connection) error {
		userPersister := r.persister.GetWebauthnUserPersister(tx)
		sessionPersister := r.persister.GetWebauthnSessionDataPersister(tx)
		credentialPersister := r.persister.GetWebauthnCredentialPersister(tx)

		service := services.NewRegistrationService(services.WebauthnServiceCreateParams{
			Ctx:                   ctx,
			Tenant:                *h.Tenant,
			WebauthnClient:        *h.WebauthnClient,
			UserPersister:         userPersister,
			SessionPersister:      sessionPersister,
			CredentialPersister:   credentialPersister,
			Generator:             h.Generator,
			AuthenticatorMetadata: r.AuthenticatorMetadata,
			UseMFA:                r.UseMFAClient,
		})

		token, userId, err := service.Finalize(parsedRequest)
		err = r.handleError(h.AuditLog, models.AuditLogWebAuthnRegistrationFinalFailed, tx, ctx, userId, nil, err)
		if err != nil {
			return err
		}

		err = h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnRegistrationFinalSucceeded, userId, nil, nil)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}

		return ctx.JSON(http.StatusOK, &response.TokenDto{Token: token})
	})
}
