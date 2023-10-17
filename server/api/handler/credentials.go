package handler

import (
	"fmt"
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/api/dto/response"
	auditlog "github.com/teamhanko/passkey-server/audit_log"
	"github.com/teamhanko/passkey-server/config"
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

func NewCredentialsHandler(cfg *config.Config, persister persistence.Persister, logger auditlog.Logger) (CredentialsHandler, error) {

	webauthnHandler, err := newWebAuthnHandler(cfg, persister, logger, nil)
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
		return err
	}

	credentialPersister := credHandler.persister.GetWebauthnCredentialPersister(nil)
	credentialModels, err := credentialPersister.GetFromUser(userId)
	if err != nil {
		return err
	}

	dtos := make([]*response.CredentialDto, len(credentialModels))
	for i, _ := range credentialModels {
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
		return err
	}

	if credential == nil {
		return &echo.HTTPError{
			Code:     http.StatusNotFound,
			Message:  fmt.Sprintf("credential with id '%s' not found.", requestDto.CredentialId),
			Internal: nil,
		}
	}

	return credHandler.persister.Transaction(func(tx *pop.Connection) error {
		credential.Name = &requestDto.Name
		credentialPersister = credHandler.persister.GetWebauthnCredentialPersister(tx)

		err = credentialPersister.Update(credential)
		if err != nil {
			return err
		}
		err := credHandler.auditLog.CreateWithConnection(tx, ctx, models.AuditLogWebAuthnCredentialUpdated, &credential.UserId, nil)
		if err != nil {
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
		return err
	}

	return credHandler.persister.Transaction(func(tx *pop.Connection) error {
		persister = credHandler.persister.GetWebauthnCredentialPersister(tx)
		err := persister.Delete(credential)
		if err != nil {
			return err
		}

		err = credHandler.auditLog.CreateWithConnection(tx, ctx, models.AuditLogWebAuthnCredentialDeleted, nil, nil)
		if err != nil {
			return err
		}

		return ctx.NoContent(http.StatusNoContent)
	})
}
