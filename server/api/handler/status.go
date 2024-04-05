package handler

import (
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/persistence"
	"net/http"
)

type StatusHandler interface {
	Get(ctx echo.Context) error
}

type statusHandler struct {
	persister persistence.Persister
}

func NewStatusHandler(persister persistence.Persister) StatusHandler {
	return &statusHandler{persister: persister}
}

func (sh *statusHandler) Get(ctx echo.Context) error {
	// random query to check DB connectivity
	_, err := sh.persister.GetJwkPersister(nil).GetAll()
	if err != nil {
		return ctx.Render(http.StatusInternalServerError, "status", map[string]bool{"dbError": true})
	}

	return ctx.Render(http.StatusOK, "status", nil)
}
