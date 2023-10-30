package admin

import (
	"github.com/labstack/echo/v4"
	"net/http"
)

type HealthHandler struct{}

func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

func (handler *HealthHandler) Ready(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, map[string]bool{"ready": true})
}

func (handler *HealthHandler) Alive(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, map[string]bool{"alive": true})
}
