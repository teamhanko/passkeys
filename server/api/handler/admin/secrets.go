package admin

import (
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	adminRequest "github.com/teamhanko/passkey-server/api/dto/admin/request"
	"github.com/teamhanko/passkey-server/api/dto/admin/response"
	"github.com/teamhanko/passkey-server/api/helper"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
)

type SecretsHandler struct {
	persister persistence.Persister
}

func (s *SecretsHandler) ListAPIKeys(ctx echo.Context) error {
	return s.listKeys(ctx, true)
}

func (s *SecretsHandler) listKeys(ctx echo.Context, isApiKey bool) error {
	var dto adminRequest.GetTenantDto
	err := ctx.Bind(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to list keys").SetInternal(err)
	}

	err = ctx.Validate(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to list keys").SetInternal(err)
	}

	tenant, err := s.findTenantByIdString(dto.TenantId)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	secrets := make([]response.SecretResponseDto, 0)
	for _, secret := range tenant.Config.Secrets {
		if secret.IsAPISecret == isApiKey {
			secrets = append(secrets, response.ToSecretResponse(&secret))
		}
	}

	return ctx.JSON(http.StatusOK, secrets)
}

func (s *SecretsHandler) findTenantByIdString(id string) (*models.Tenant, error) {
	return helper.FindTenantByIdString(id, s.persister.GetTenantPersister(nil))
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

	tenant, err := s.findTenantByIdString(dto.TenantId)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	secret, err := dto.ToModel(&tenant.Config, isApiKey)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	err = s.persister.GetSecretsPersister(nil).Create(secret)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return ctx.JSON(http.StatusCreated, response.ToSecretResponse(secret))
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

	tenant, err := s.findTenantByIdString(dto.TenantId)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	secretId, err := uuid.FromString(dto.SecretId)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to parse key id").SetInternal(err)
	}

	var foundSecret *models.Secret
	for _, secret := range tenant.Config.Secrets {
		if secret.ID == secretId && secret.IsAPISecret == isApiKey {
			foundSecret = &secret
		}
	}

	if foundSecret == nil {
		return echo.NewHTTPError(http.StatusNotFound, fmt.Errorf("secret with ID '%s' not found", dto.SecretId))
	}

	err = s.persister.GetSecretsPersister(nil).Delete(foundSecret)
	if err != nil {
		ctx.Logger().Error(err)
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
