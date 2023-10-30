package handler

import (
	"github.com/labstack/echo/v4"
	hankoJwk "github.com/teamhanko/passkey-server/crypto/jwk"
	"net/http"
)

type WellKnownHandler struct{}

func NewWellKnownHandler() *WellKnownHandler {
	return &WellKnownHandler{}
}

func (h *WellKnownHandler) GetPublicKeys(ctx echo.Context) error {
	manager := ctx.Get("jwk_manager").(hankoJwk.Manager)
	keys, err := manager.GetPublicKeys()
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	ctx.Response().Header().Add("Cache-Control", "max-age=600")
	return ctx.JSON(http.StatusOK, keys)
}
