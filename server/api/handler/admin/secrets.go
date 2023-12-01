package admin

import (
	"github.com/labstack/echo/v4"
	adminRequest "github.com/teamhanko/passkey-server/api/dto/admin/request"
	"github.com/teamhanko/passkey-server/api/helper"
	"github.com/teamhanko/passkey-server/api/services/admin"
	"github.com/teamhanko/passkey-server/persistence"
	"net/http"
)

type SecretsHandler struct {
	persister persistence.Persister
}

func (s *SecretsHandler) ListAPIKeys(ctx echo.Context) error {
	return s.listKeys(ctx, true)
}

func (s *SecretsHandler) listKeys(ctx echo.Context, isApiKey bool) error {
	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	service := admin.NewSecretService(ctx, *h.Tenant, nil)
	return ctx.JSON(http.StatusOK, service.List(isApiKey))
}

func (s *SecretsHandler) CreateAPIKey(ctx echo.Context) error {
	return s.createKey(ctx, true)
}

func (s *SecretsHandler) createKey(ctx echo.Context, isApiKey bool) error {
	var dto adminRequest.CreateSecretDto
	err := ctx.Bind(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to create key").SetInternal(err)
	}

	err = ctx.Validate(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to create key").SetInternal(err)
	}

	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	service := admin.NewSecretService(ctx, *h.Tenant, s.persister.GetSecretsPersister(nil))
	secretDto, err := service.Create(dto, isApiKey)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusCreated, secretDto)
}

func (s *SecretsHandler) RemoveAPIKey(ctx echo.Context) error {
	return s.removeKey(ctx, true)
}

func (s *SecretsHandler) removeKey(ctx echo.Context, isApiKey bool) error {
	var dto adminRequest.RemoveSecretDto
	err := ctx.Bind(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to remove key").SetInternal(err)
	}

	err = ctx.Validate(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to remove key").SetInternal(err)
	}

	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	service := admin.NewSecretService(ctx, *h.Tenant, s.persister.GetSecretsPersister(nil))
	err = service.Remove(dto, isApiKey)
	if err != nil {
		return err
	}

	return ctx.NoContent(http.StatusNoContent)
}

func (s *SecretsHandler) ListJWKKeys(ctx echo.Context) error {
	return s.listKeys(ctx, false)
}

func (s *SecretsHandler) CreateJWKKey(ctx echo.Context) error {
	return s.createKey(ctx, false)
}

func (s *SecretsHandler) RemoveJWKKey(ctx echo.Context) error {
	return s.removeKey(ctx, false)
}

func NewSecretsHandler(persister persistence.Persister) SecretsHandler {
	return SecretsHandler{
		persister: persister,
	}
}
