package handler

import (
	"errors"
	"github.com/gobuffalo/pop/v6"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/request"
	auditlog "github.com/teamhanko/passkey-server/audit_log"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
)

type WebauthnHandler interface {
	Init(ctx echo.Context) error
	Finish(ctx echo.Context) error
}

type webauthnHandler struct {
	persister    persistence.Persister
	UseMFAClient bool
}

func newWebAuthnHandler(persister persistence.Persister, useMFAClient bool) *webauthnHandler {
	return &webauthnHandler{
		persister:    persister,
		UseMFAClient: useMFAClient,
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
