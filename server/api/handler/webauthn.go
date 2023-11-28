package handler

import (
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/intern"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/persistence"
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
		return nil, echo.NewHTTPError(http.StatusBadRequest, fmt.Errorf("unable to process request: %w", err))
	}

	err = ctx.Validate(&requestDto)
	if err != nil {
		ctx.Logger().Error(err)
		return nil, echo.NewHTTPError(http.StatusBadRequest, fmt.Errorf("unable to validate request: %w", err))
	}

	return &requestDto, nil
}
