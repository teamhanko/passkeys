package handler

import (
	"github.com/labstack/echo/v4"
	hankoJwk "github.com/teamhanko/passkey-server/crypto/jwk"
	"net/http"
)

type WellKnownHandler struct {
	jwkManager hankoJwk.Manager
}

func NewWellKnownHandler(jwkManager hankoJwk.Manager) *WellKnownHandler {
	return &WellKnownHandler{
		jwkManager: jwkManager,
	}
}

func (h *WellKnownHandler) GetPublicKeys(c echo.Context) error {
	keys, err := h.jwkManager.GetPublicKeys()
	if err != nil {
		return err
	}

	c.Response().Header().Add("Cache-Control", "max-age=600")
	return c.JSON(http.StatusOK, keys)
}
