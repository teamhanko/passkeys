package handler

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/persistence"
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

func BindAndValidateRequest[I request.CredentialRequest | request.InitRegistrationDto](ctx echo.Context) (*I, error) {
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
