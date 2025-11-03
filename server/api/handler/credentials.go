package handler

import (
	"net/http"

	"github.com/gobuffalo/pop/v6"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/api/dto/response"
	"github.com/teamhanko/passkey-server/api/helper"
	"github.com/teamhanko/passkey-server/api/services"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type CredentialsHandler interface {
	List(ctx echo.Context) error
	Get(ctx echo.Context) error
	Update(ctx echo.Context) error
	Delete(ctx echo.Context) error
}

type credentialsHandler struct {
	*webauthnHandler
}

func NewCredentialsHandler(persister persistence.Persister) CredentialsHandler {
	webauthnHandler := newWebAuthnHandler(persister, false)

	return &credentialsHandler{
		webauthnHandler,
	}
}

func (credHandler *credentialsHandler) List(ctx echo.Context) error {
	requestDto, err := BindAndValidateRequest[request.ListCredentialsDto](ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	if requestDto.Page <= 0 {
		requestDto.Page = 1
	}

	if requestDto.PerPage <= 0 {
		requestDto.PerPage = 20
	}

	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return credHandler.persister.Transaction(func(tx *pop.Connection) error {
		user, err := credHandler.persister.GetWebauthnUserPersister(tx).GetByUserId(requestDto.UserId, h.Tenant.ID)
		if err != nil {
			ctx.Logger().Error(err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Unable to get credentials for user").SetInternal(err)
		}

		if user == nil {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}

		service := services.NewCredentialService(ctx, *h.Tenant, credHandler.persister.GetWebauthnCredentialPersister(tx))
		dtos, err := service.List(*requestDto)
		if err != nil {
			return err
		}

		return ctx.JSON(http.StatusOK, dtos)
	})

}

func (credHandler *credentialsHandler) Get(ctx echo.Context) error {
	requestDto, err := BindAndValidateRequest[request.GetCredentialDto](ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	service := services.NewCredentialService(ctx, *h.Tenant, credHandler.persister.GetWebauthnCredentialPersister(nil))
	credential, err := service.Get(*requestDto)
	if err != nil {
		return err
	}

	credentialDto := response.CredentialDtoFromModel(*credential)

	return ctx.JSON(http.StatusOK, credentialDto)
}

func (credHandler *credentialsHandler) Update(ctx echo.Context) error {
	requestDto, err := BindAndValidateRequest[request.UpdateCredentialsDto](ctx)
	if err != nil {
		return err
	}

	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return credHandler.persister.Transaction(func(tx *pop.Connection) error {
		credentialPersister := credHandler.persister.GetWebauthnCredentialPersister(tx)

		service := services.NewCredentialService(ctx, *h.Tenant, credentialPersister)
		credential, err := service.Update(*requestDto)
		if err != nil {
			return err
		}

		err = h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnCredentialUpdated, &credential.UserId, nil, nil)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}

		return ctx.NoContent(http.StatusNoContent)
	})
}

func (credHandler *credentialsHandler) Delete(ctx echo.Context) error {
	requestDto, err := BindAndValidateRequest[request.DeleteCredentialsDto](ctx)
	if err != nil {
		return err
	}

	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return credHandler.persister.Transaction(func(tx *pop.Connection) error {
		credentialPersister := credHandler.persister.GetWebauthnCredentialPersister(tx)

		service := services.NewCredentialService(ctx, *h.Tenant, credentialPersister)
		err := service.Delete(*requestDto)
		if err != nil {
			return err
		}

		err = h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnCredentialDeleted, nil, nil, nil)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}

		return ctx.NoContent(http.StatusNoContent)
	})
}
