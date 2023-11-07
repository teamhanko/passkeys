package handler

import (
	"fmt"
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/api/dto/response"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
)

type CredentialsHandler interface {
	List(ctx echo.Context) error
	Update(ctx echo.Context) error
	Delete(ctx echo.Context) error
}

type credentialsHandler struct {
	*webauthnHandler
}

func NewCredentialsHandler(persister persistence.Persister) (CredentialsHandler, error) {

	webauthnHandler, err := newWebAuthnHandler(persister)
	if err != nil {
		return nil, err
	}

	return &credentialsHandler{
		webauthnHandler,
	}, nil
}

func (credHandler *credentialsHandler) List(ctx echo.Context) error {
	requestDto, err := BindAndValidateRequest[request.ListCredentialsDto](ctx)
	if err != nil {
		return err
	}

	userId, err := uuid.FromString(requestDto.UserId)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	credentialPersister := credHandler.persister.GetWebauthnCredentialPersister(nil)
	credentialModels, err := credentialPersister.GetFromUser(userId)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	dtos := make([]*response.CredentialDto, len(credentialModels))
	for i := range credentialModels {
		dtos[i] = response.CredentialDtoFromModel(credentialModels[i])
	}

	return ctx.JSON(http.StatusOK, dtos)
}

func (credHandler *credentialsHandler) Update(ctx echo.Context) error {
	requestDto, err := BindAndValidateRequest[request.UpdateCredentialsDto](ctx)
	if err != nil {
		return err
	}

	credentialPersister := credHandler.persister.GetWebauthnCredentialPersister(nil)

	credential, err := credentialPersister.Get(requestDto.CredentialId)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	if credential == nil {
		return echo.NewHTTPError(http.StatusNotFound, &echo.HTTPError{
			Code:     http.StatusNotFound,
			Message:  fmt.Sprintf("credential with id '%s' not found.", requestDto.CredentialId),
			Internal: nil,
		})
	}

	h, err := GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return credHandler.persister.Transaction(func(tx *pop.Connection) error {
		credential.Name = &requestDto.Name
		credentialPersister = credHandler.persister.GetWebauthnCredentialPersister(tx)

		err = credentialPersister.Update(credential)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}
		err := h.auditLog.CreateWithConnection(tx, ctx, h.tenant, models.AuditLogWebAuthnCredentialUpdated, &credential.UserId, nil)
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

	persister := credHandler.persister.GetWebauthnCredentialPersister(nil)
	credential, err := persister.Get(requestDto.Id)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	h, err := GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return credHandler.persister.Transaction(func(tx *pop.Connection) error {
		persister = credHandler.persister.GetWebauthnCredentialPersister(tx)
		err := persister.Delete(credential)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}

		err = h.auditLog.CreateWithConnection(tx, ctx, h.tenant, models.AuditLogWebAuthnCredentialDeleted, nil, nil)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}

		return ctx.NoContent(http.StatusNoContent)
	})
}
