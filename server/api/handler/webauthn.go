package handler

import (
	"errors"
	"fmt"
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/intern"
	"github.com/teamhanko/passkey-server/api/dto/request"
	auditlog "github.com/teamhanko/passkey-server/audit_log"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
	"net/http"
)

type WebauthnHandler interface {
	Init(ctx echo.Context) error
	Finish(ctx echo.Context) error
}

type webauthnHandler struct {
	persister persistence.Persister
}

func newWebAuthnHandler(persister persistence.Persister) *webauthnHandler {
	return &webauthnHandler{
		persister: persister,
	}
}

func (w *webauthnHandler) handleError(logger auditlog.Logger, logType models.AuditLogType, tx *pop.Connection, ctx echo.Context, userId *string, transaction *models.Transaction, logError error) error {
	if logError != nil {
		auditErr := logger.CreateWithConnection(tx, logType, userId, transaction, logError)
		if auditErr != nil {
			ctx.Logger().Error(auditErr)
			return auditErr
		}

		var httpError *echo.HTTPError
		if errors.As(logError, &httpError) {
			return logError
		}

		return errors.New("unable to process request")
	}

	return nil
}

func (w *webauthnHandler) getWebauthnUserByUserHandle(userHandle string, tenantId uuid.UUID, persister persisters.WebauthnUserPersister) (*intern.WebauthnUser, error) {
	user, err := persister.GetByUserId(userHandle, tenantId)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	return intern.NewWebauthnUser(*user), nil
}

func (w *webauthnHandler) convertUserHandle(userHandle []byte) string {
	userId := string(userHandle)
	userUuid, err := uuid.FromBytes(userHandle)
	if err == nil {
		userId = userUuid.String()
	}

	return userId
}

func BindAndValidateRequest[I request.CredentialRequests | request.WebauthnRequests](ctx echo.Context) (*I, error) {
	var requestDto I
	err := ctx.Bind(&requestDto)
	if err != nil {
		ctx.Logger().Error(err)
		return nil, echo.NewHTTPError(http.StatusBadRequest, "unable to process request").SetInternal(err)
	}

	err = ctx.Validate(&requestDto)
	if err != nil {
		ctx.Logger().Error(err)
		return nil, echo.NewHTTPError(http.StatusBadRequest, "unable to validate request").SetInternal(err)
	}

	return &requestDto, nil
}
