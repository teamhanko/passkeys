package admin

import (
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/admin/request"
	"github.com/teamhanko/passkey-server/api/dto/admin/response"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
	"net/http"
)

type SecretService interface {
	List(isApiSecret bool) response.SecretResponseListDto
	Create(dto request.CreateSecretDto, isApiSecret bool) (*response.SecretResponseDto, error)
	Remove(dto request.RemoveSecretDto, isApiKey bool) error
}

type secretService struct {
	logger echo.Logger
	tenant models.Tenant

	tenantPersister persisters.TenantPersister
	secretPersister persisters.SecretsPersister
}

func NewSecretService(ctx echo.Context, tenant models.Tenant, secretPersister persisters.SecretsPersister) SecretService {
	return &secretService{
		logger:          ctx.Logger(),
		tenant:          tenant,
		secretPersister: secretPersister,
	}
}

func (ses *secretService) List(isApiSecret bool) response.SecretResponseListDto {
	secrets := make(response.SecretResponseListDto, 0)
	for _, secret := range ses.tenant.Config.Secrets {
		if secret.IsAPISecret == isApiSecret {
			secrets = append(secrets, *response.ToSecretResponse(&secret))
		}
	}

	return secrets
}

func (ses *secretService) Create(dto request.CreateSecretDto, isApiSecret bool) (*response.SecretResponseDto, error) {
	secret, err := dto.ToModel(&ses.tenant.Config, isApiSecret)
	if err != nil {
		ses.logger.Error(err)
		return nil, err
	}

	foundSecret, err := ses.secretPersister.GetByName(secret.Name, secret.IsAPISecret)
	if err != nil {
		ses.logger.Error(err)
		return nil, err
	}

	if foundSecret.ID != uuid.Nil {
		return nil, echo.NewHTTPError(http.StatusConflict, "Secret with this name already exists")
	}

	err = ses.secretPersister.Create(secret)
	if err != nil {
		ses.logger.Error(err)
		return nil, err
	}

	responseDto := response.ToSecretResponse(secret)
	return responseDto, nil
}

func (ses *secretService) Remove(dto request.RemoveSecretDto, isApiKey bool) error {
	secretId, err := uuid.FromString(dto.SecretId)
	if err != nil {
		ses.logger.Error(err)
		return err
	}

	var foundSecret *models.Secret
	for _, secret := range ses.tenant.Config.Secrets {
		if secret.ID == secretId && secret.IsAPISecret == isApiKey {
			s := secret
			foundSecret = &s
		}
	}

	if foundSecret == nil {
		return echo.NewHTTPError(http.StatusNotFound, fmt.Errorf("secret with ID '%s' not found", dto.SecretId))
	}

	err = ses.secretPersister.Delete(foundSecret)
	if err != nil {
		ses.logger.Error(err)
		return err
	}

	return nil
}
