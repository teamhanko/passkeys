package services

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/api/dto/response"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
	"net/http"
)

type CredentialService interface {
	List(dto request.ListCredentialsDto) (response.CredentialDtoList, error)
	Update(dto request.UpdateCredentialsDto) (*models.WebauthnCredential, error)
	Delete(dto request.DeleteCredentialsDto) error
}

type credentialService struct {
	*BaseService
}

func NewCredentialService(ctx echo.Context, tenant models.Tenant, credentialPersister persisters.WebauthnCredentialPersister) CredentialService {
	return &credentialService{
		&BaseService{
			logger:              ctx.Logger(),
			tenant:              tenant,
			credentialPersister: credentialPersister,
		},
	}
}

func (cs *credentialService) List(dto request.ListCredentialsDto) (response.CredentialDtoList, error) {
	credentialModels, err := cs.credentialPersister.GetFromUser(dto.UserId, cs.tenant.ID)
	if err != nil {
		cs.logger.Error(err)
		return nil, err
	}

	dtos := make(response.CredentialDtoList, len(credentialModels))
	for i := range credentialModels {
		dtos[i] = response.CredentialDtoFromModel(credentialModels[i])
	}

	return dtos, nil
}

func (cs *credentialService) Update(dto request.UpdateCredentialsDto) (*models.WebauthnCredential, error) {

	credential, err := cs.credentialPersister.Get(dto.CredentialId, cs.tenant.ID)
	if err != nil {
		cs.logger.Error(err)
		return nil, echo.NewHTTPError(http.StatusBadRequest, err)
	}

	if credential == nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, fmt.Errorf("credential with id '%s' not found", dto.CredentialId))
	}

	credential.Name = &dto.Name
	err = cs.credentialPersister.Update(credential)
	if err != nil {
		cs.logger.Error(err)
		return nil, err
	}

	return credential, nil
}

func (cs *credentialService) Delete(dto request.DeleteCredentialsDto) error {
	credential, err := cs.credentialPersister.Get(dto.CredentialId, cs.tenant.ID)
	if err != nil {
		cs.logger.Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	if credential == nil {
		return echo.NewHTTPError(http.StatusNotFound, fmt.Errorf("credential with id '%s' not found", dto.CredentialId))
	}

	err = cs.credentialPersister.Delete(credential)
	if err != nil {
		cs.logger.Error(err)
		return err
	}

	return nil
}
