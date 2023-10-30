package admin

import (
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/persistence"
	"net/http"
)

type StatusHandler struct {
	persister persistence.Persister
}

func NewStatusHandler(persister persistence.Persister) *StatusHandler {
	return &StatusHandler{
		persister: persister,
	}
}

func (h *StatusHandler) Status(ctx echo.Context) error {
	// random query to check DB connectivity
	_, err := h.persister.GetJwkPersister(nil).GetAll()
	status := http.StatusOK
	if err != nil {
		ctx.Logger().Error(err)
		status = http.StatusInternalServerError
	}

	return ctx.Render(status, "status", map[string]bool{"dbError": err != nil})
}
