package admin

import (
	"fmt"
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/admin/request"
	"github.com/teamhanko/passkey-server/api/dto/admin/response"
	"github.com/teamhanko/passkey-server/api/helper"
	"github.com/teamhanko/passkey-server/api/pagination"
	"github.com/teamhanko/passkey-server/crypto"
	hankoJwk "github.com/teamhanko/passkey-server/crypto/jwk"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type TenantHandler struct {
	persister persistence.Persister
}

func (th *TenantHandler) List(ctx echo.Context) error {
	tenants, err := th.persister.GetTenantPersister(nil).List()
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	tenantList := make([]response.ListTenantResponse, 0)
	for _, tenant := range tenants {
		tenantList = append(tenantList, response.ToListTenantResponse(&tenant))
	}

	return ctx.JSON(http.StatusOK, tenantList)
}

func (th *TenantHandler) Create(ctx echo.Context) error {
	var dto request.CreateTenantDto
	err := ctx.Bind(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to create tenant").SetInternal(err)
	}

	// transform dto to model
	tenantModel := dto.ToModel()
	configModel := dto.Config.ToModel(tenantModel)
	corsModel := dto.Config.Cors.ToModel(configModel)
	webauthnConfigModel := dto.Config.Webauthn.ToModel(configModel)
	relyingPartyModel := dto.Config.Webauthn.RelyingParty.ToModel(webauthnConfigModel)

	apiSecretModel, err := createSecret("Initial API Key", configModel.ID, true)
	if err != nil {
		ctx.Logger().Error(err)
		return fmt.Errorf("unable to create new api key: %w", err)
	}

	jwkSecretModel, err := createSecret("Initial JWK Key", configModel.ID, false)
	if err != nil {
		ctx.Logger().Error(err)
		return fmt.Errorf("unable to create new jwk key: %w", err)
	}

	return th.persister.GetConnection().Transaction(func(tx *pop.Connection) error {
		tenantPersister := th.persister.GetTenantPersister(tx)
		secretPersister := th.persister.GetSecretsPersister(tx)

		err = tenantPersister.Create(&tenantModel)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}

		err = th.persistConfig(tx, &configModel, &corsModel, &webauthnConfigModel, &relyingPartyModel)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}

		err = secretPersister.Create(apiSecretModel)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}

		err = secretPersister.Create(jwkSecretModel)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}

		jwks := []string{jwkSecretModel.Key}
		_, err := hankoJwk.NewDefaultManager(jwks, tenantModel.ID, th.persister.GetJwkPersister(tx))
		if err != nil {
			ctx.Logger().Error(err)
			return echo.NewHTTPError(http.StatusInternalServerError, "unable to initialize jwt generator").SetInternal(err)
		}

		return ctx.JSON(http.StatusCreated, response.ToCreateTenantResponse(&tenantModel, apiSecretModel))
	})
}

func (th *TenantHandler) Get(ctx echo.Context) error {
	var dto request.GetTenantDto
	err := ctx.Bind(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to get tenant").SetInternal(err)
	}

	err = ctx.Validate(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to get tenant").SetInternal(err)
	}

	tenant, err := th.findTenantByIdString(dto.TenantId)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return ctx.JSON(http.StatusOK, response.ToGetTenantResponse(tenant))
}

func (th *TenantHandler) findTenantByIdString(id string) (*models.Tenant, error) {
	return helper.FindTenantByIdString(id, th.persister.GetTenantPersister(nil))
}

func (th *TenantHandler) Update(ctx echo.Context) error {
	var dto request.UpdateTenantDto
	err := ctx.Bind(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to update tenant").SetInternal(err)
	}

	err = ctx.Validate(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to update tenant").SetInternal(err)
	}

	tenant, err := th.findTenantByIdString(dto.TenantId)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	tenant.DisplayName = dto.DisplayName
	tenant.UpdatedAt = time.Now()

	err = th.persister.GetTenantPersister(nil).Update(tenant)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return ctx.NoContent(http.StatusNoContent)
}

func (th *TenantHandler) Remove(ctx echo.Context) error {
	var dto request.GetTenantDto
	err := ctx.Bind(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to remove tenant").SetInternal(err)
	}

	err = ctx.Validate(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to remove tenant").SetInternal(err)
	}

	tenant, err := th.findTenantByIdString(dto.TenantId)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	err = th.persister.GetTenantPersister(nil).Delete(tenant)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return ctx.NoContent(http.StatusNoContent)
}

func (th *TenantHandler) UpdateConfig(ctx echo.Context) error {
	var dto request.UpdateConfigDto
	err := ctx.Bind(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to update tenant config").SetInternal(err)
	}

	err = ctx.Validate(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to update tenant config").SetInternal(err)
	}

	tenant, err := th.findTenantByIdString(dto.TenantId)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return th.persister.GetConnection().Transaction(func(tx *pop.Connection) error {
		configPersister := th.persister.GetConfigPersister(tx)
		secretPersister := th.persister.GetSecretsPersister(tx)

		config := tenant.Config
		newConfig := dto.ToModel(*tenant)
		corsModel := dto.Cors.ToModel(newConfig)
		webauthnConfigModel := dto.Webauthn.ToModel(newConfig)
		relyingPartyModel := dto.Webauthn.RelyingParty.ToModel(webauthnConfigModel)

		err = th.persistConfig(tx, &newConfig, &corsModel, &webauthnConfigModel, &relyingPartyModel)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}

		for _, secret := range config.Secrets {
			secret.ConfigID = newConfig.ID
			err = secretPersister.Update(&secret)
			if err != nil {
				ctx.Logger().Error(err)
				return err
			}
		}

		err = configPersister.Delete(&config)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}

		return ctx.NoContent(http.StatusNoContent)
	})
}

func (th *TenantHandler) persistConfig(tx *pop.Connection, config *models.Config, cors *models.Cors, webauthn *models.WebauthnConfig, rp *models.RelyingParty) error {
	configPersister := th.persister.GetConfigPersister(tx)
	corsPersister := th.persister.GetCorsPersister(tx)
	webauthnConfigPersister := th.persister.GetWebauthnConfigPersister(tx)
	relyingPartyPersister := th.persister.GetWebauthnRelyingPartyPersister(tx)
	auditLogConfigPersister := th.persister.GetAuditLogConfigPersister(tx)

	err := configPersister.Create(config)
	if err != nil {
		return err
	}

	err = corsPersister.Create(cors)
	if err != nil {
		return err
	}

	err = webauthnConfigPersister.Create(webauthn)
	if err != nil {
		return err
	}

	err = relyingPartyPersister.Create(rp)
	if err != nil {
		return err
	}

	err = auditLogConfigPersister.Create(&config.AuditLogConfig)
	if err != nil {
		return err
	}

	return nil
}

func (th *TenantHandler) ListAuditLog(ctx echo.Context) error {
	var dto request.ListAuditLogDto
	err := ctx.Bind(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to list audit logs").SetInternal(err)
	}

	err = ctx.Validate(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to list audit logs").SetInternal(err)
	}

	if dto.Page == 0 {
		dto.Page = 1
	}

	if dto.PerPage == 0 {
		dto.PerPage = 20
	}

	options := persisters.AuditLogOptions{
		Page:     dto.Page,
		PerPage:  dto.PerPage,
		Start:    dto.StartTime,
		End:      dto.EndTime,
		Types:    dto.Types,
		UserId:   dto.UserId,
		Ip:       dto.IP,
		Search:   dto.SearchString,
		TenantId: dto.TenantId,
	}

	auditLogs, err := th.persister.GetAuditLogPersister(nil).List(options)
	if err != nil {
		ctx.Logger().Error(err)
		return fmt.Errorf("failed to get list of audit logs: %w", err)
	}

	logCount, err := th.persister.GetAuditLogPersister(nil).Count(options)
	if err != nil {
		ctx.Logger().Error(err)
		return fmt.Errorf("failed to get total count of audit logs: %w", err)
	}

	u, _ := url.Parse(fmt.Sprintf("%s://%s%s", ctx.Scheme(), ctx.Request().Host, ctx.Request().RequestURI))

	ctx.Response().Header().Set("Link", pagination.CreateHeader(u, logCount, options.Page, options.PerPage))
	ctx.Response().Header().Set("X-Total-Count", strconv.FormatInt(int64(logCount), 10))

	if auditLogs == nil {
		auditLogs = make(models.AuditLogs, 0)
	}

	return ctx.JSON(http.StatusOK, auditLogs)
}

func NewTenantHandler(persister persistence.Persister) *TenantHandler {
	return &TenantHandler{
		persister: persister,
	}
}

func createSecret(name string, configId uuid.UUID, isAPIKey bool) (*models.Secret, error) {
	secretId, err := uuid.NewV4()
	if err != nil {
		return nil, fmt.Errorf("unable to create id for a new key: %w", err)
	}

	secretKey, err := crypto.GenerateRandomStringURLSafe(64)
	if err != nil {
		return nil, fmt.Errorf("unable to create key: %w", err)
	}

	now := time.Now()

	return &models.Secret{
		ID:          secretId,
		Name:        name,
		Key:         secretKey,
		ConfigID:    configId,
		IsAPISecret: isAPIKey,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}
