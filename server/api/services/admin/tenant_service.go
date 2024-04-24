package admin

import (
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/admin/request"
	"github.com/teamhanko/passkey-server/api/dto/admin/response"
	"github.com/teamhanko/passkey-server/crypto"
	hankoJwk "github.com/teamhanko/passkey-server/crypto/jwk"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
	"time"
)

type TenantService interface {
	List() (*response.ListTenantResponses, error)
	Create(dto request.CreateTenantDto) (*response.CreateTenantResponse, error)
	Update(dto request.UpdateTenantDto) error
	UpdateConfig(dto request.UpdateConfigDto) error
	ListAuditLogs(dto request.ListAuditLogDto) (models.AuditLogs, int, error)
}

type tenantService struct {
	logger echo.Logger
	tenant *models.Tenant

	tenantPersister         persisters.TenantPersister
	configPersister         persisters.ConfigPersister
	corsPersister           persisters.CorsPersister
	webauthnConfigPersister persisters.WebauthnConfigPersister
	relyingPartyPerister    persisters.WebauthnRelyingPartyPersister
	auditConfigPersister    persisters.AuditLogConfigPersister
	secretPersister         persisters.SecretsPersister
	jwkPersister            persisters.JwkPersister
	auditLogPersister       persisters.AuditLogPersister
	mfaConfigPersister      persisters.MFAConfigPersister
}

type CreateTenantServiceParams struct {
	Ctx    echo.Context
	Tenant *models.Tenant

	TenantPersister         persisters.TenantPersister
	ConfigPersister         persisters.ConfigPersister
	CorsPersister           persisters.CorsPersister
	WebauthnConfigPersister persisters.WebauthnConfigPersister
	RelyingPartyPerister    persisters.WebauthnRelyingPartyPersister
	AuditConfigPersister    persisters.AuditLogConfigPersister
	SecretPersister         persisters.SecretsPersister
	JwkPersister            persisters.JwkPersister
	AuditLogPersister       persisters.AuditLogPersister
	MFAConfigPersister      persisters.MFAConfigPersister
}

func NewTenantService(params CreateTenantServiceParams) TenantService {
	return &tenantService{
		logger: params.Ctx.Logger(),
		tenant: params.Tenant,

		tenantPersister:         params.TenantPersister,
		configPersister:         params.ConfigPersister,
		corsPersister:           params.CorsPersister,
		webauthnConfigPersister: params.WebauthnConfigPersister,
		relyingPartyPerister:    params.RelyingPartyPerister,
		auditConfigPersister:    params.AuditConfigPersister,
		secretPersister:         params.SecretPersister,
		jwkPersister:            params.JwkPersister,
		auditLogPersister:       params.AuditLogPersister,
		mfaConfigPersister:      params.MFAConfigPersister,
	}
}

func (ts *tenantService) List() (*response.ListTenantResponses, error) {
	tenants, err := ts.tenantPersister.List()
	if err != nil {
		ts.logger.Error(err)
		return nil, err
	}

	tenantList := make(response.ListTenantResponses, 0)
	for _, tenant := range tenants {
		t := tenant
		tenantList = append(tenantList, response.ToListTenantResponse(&t))
	}

	return &tenantList, nil
}

func (ts *tenantService) Create(dto request.CreateTenantDto) (*response.CreateTenantResponse, error) {
	// transform dto to model
	tenantModel := dto.ToModel()
	configModel := dto.Config.ToModel(tenantModel)
	corsModel := dto.Config.Cors.ToModel(configModel)
	passkeyConfigModel := dto.Config.Passkey.ToModel(configModel)
	relyingPartyModel := dto.Config.Passkey.RelyingParty.ToModel(passkeyConfigModel)

	var mfaConfigModel models.MfaConfig
	if dto.Config.Mfa == nil {
		mfaConfigModel = dto.Config.Passkey.ToMfaModel(configModel)
	} else {
		mfaConfigModel = dto.Config.Mfa.ToModel(configModel)
	}

	err := ts.tenantPersister.Create(&tenantModel)
	if err != nil {
		ts.logger.Error(err)
		return nil, err
	}

	err = ts.persistConfig(
		&configModel,
		&corsModel,
		&passkeyConfigModel,
		&relyingPartyModel,
		&mfaConfigModel,
	)

	var apiSecretModel *models.Secret = nil
	if dto.CreateApiKey {
		apiSecretModel, err = ts.createSecret("Initial API Key", configModel.ID, true)
		if err != nil {
			ts.logger.Error(err)
			return nil, fmt.Errorf("unable to create new api key: %w", err)
		}
	}

	jwkSecretModel, err := ts.createSecret("Initial JWK Key", configModel.ID, false)
	if err != nil {
		ts.logger.Error(err)
		return nil, fmt.Errorf("unable to create new jwk key: %w", err)
	}

	jwks := []string{jwkSecretModel.Key}
	_, err = hankoJwk.NewDefaultManager(jwks, tenantModel.ID, ts.jwkPersister)
	if err != nil {
		ts.logger.Error(err)
		return nil, fmt.Errorf("unable to initialize jwt generator: %w", err)
	}

	createResponse := response.ToCreateTenantResponse(&tenantModel, apiSecretModel)

	return &createResponse, nil
}

func (ts *tenantService) createSecret(name string, configId uuid.UUID, isAPIKey bool) (*models.Secret, error) {
	secretId, err := uuid.NewV4()
	if err != nil {
		return nil, fmt.Errorf("unable to create id for a new key: %w", err)
	}

	secretKey, err := crypto.GenerateRandomStringURLSafe(64)
	if err != nil {
		return nil, fmt.Errorf("unable to create key: %w", err)
	}

	now := time.Now()

	model := &models.Secret{
		ID:          secretId,
		Name:        name,
		Key:         secretKey,
		ConfigID:    configId,
		IsAPISecret: isAPIKey,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	err = ts.secretPersister.Create(model)
	if err != nil {
		return nil, err
	}

	return model, nil
}

func (ts *tenantService) persistConfig(config *models.Config, cors *models.Cors, webauthn *models.WebauthnConfig, rp *models.RelyingParty, mfaConfig *models.MfaConfig) error {
	err := ts.configPersister.Create(config)
	if err != nil {
		return err
	}

	err = ts.corsPersister.Create(cors)
	if err != nil {
		return err
	}

	err = ts.webauthnConfigPersister.Create(webauthn)
	if err != nil {
		return err
	}

	err = ts.relyingPartyPerister.Create(rp)
	if err != nil {
		return err
	}

	err = ts.mfaConfigPersister.Create(mfaConfig)
	if err != nil {
		return err
	}

	err = ts.auditConfigPersister.Create(&config.AuditLogConfig)
	if err != nil {
		return err
	}

	return nil
}

func (ts *tenantService) Update(dto request.UpdateTenantDto) error {
	ts.tenant.DisplayName = dto.DisplayName
	ts.tenant.UpdatedAt = time.Now()

	err := ts.tenantPersister.Update(ts.tenant)
	if err != nil {
		ts.logger.Error(err)
		return err
	}

	return nil
}

func (ts *tenantService) UpdateConfig(dto request.UpdateConfigDto) error {
	config := ts.tenant.Config
	newConfig := dto.ToModel(*ts.tenant)
	corsModel := dto.Cors.ToModel(newConfig)
	webauthnConfigModel := dto.Passkey.ToModel(newConfig)
	relyingPartyModel := dto.Passkey.RelyingParty.ToModel(webauthnConfigModel)

	var mfaConfigModel models.MfaConfig
	if dto.Mfa == nil {
		mfaConfigModel = dto.Passkey.ToMfaModel(newConfig)
	} else {
		mfaConfigModel = dto.Mfa.ToModel(newConfig)
	}

	err := ts.persistConfig(
		&newConfig,
		&corsModel,
		&webauthnConfigModel,
		&relyingPartyModel,
		&mfaConfigModel,
	)

	if err != nil {
		ts.logger.Error(err)
		return err
	}

	for _, secret := range config.Secrets {
		s := secret
		s.ConfigID = newConfig.ID
		err = ts.secretPersister.Update(&s)
		if err != nil {
			ts.logger.Error(err)
			return err
		}
	}

	err = ts.configPersister.Delete(&config)
	if err != nil {
		ts.logger.Error(err)
		return err
	}

	return nil
}

func (ts *tenantService) ListAuditLogs(dto request.ListAuditLogDto) (models.AuditLogs, int, error) {
	options := persisters.AuditLogOptions{
		Page:     dto.Page,
		PerPage:  dto.PerPage,
		Start:    dto.StartTime,
		End:      dto.EndTime,
		Types:    dto.Types,
		UserId:   dto.UserId,
		Ip:       dto.IP,
		Search:   dto.SearchString,
		TenantId: ts.tenant.ID.String(),
	}

	auditLogs := make(models.AuditLogs, 0)

	auditLogEntries, err := ts.auditLogPersister.List(options)
	if err != nil {
		ts.logger.Error(err)
		return auditLogs, 0, fmt.Errorf("failed to get list of audit logs: %w", err)
	}

	auditLogs = append(auditLogs, auditLogEntries...)

	logCount, err := ts.auditLogPersister.Count(options)
	if err != nil {
		ts.logger.Error(err)
		return auditLogs, 0, fmt.Errorf("failed to get total count of audit logs: %w", err)
	}

	return auditLogs, logCount, nil
}
