package services

import (
	"errors"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/intern"
	"github.com/teamhanko/passkey-server/mapper"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
	"strings"
	"time"
)

type RegistrationService interface {
	Initialize(user *models.WebauthnUser) (*protocol.CredentialCreation, string, error)
	Finalize(req *protocol.ParsedCredentialCreationData) (string, *string, error)
}

type registrationService struct {
	WebauthnService
	mapper.AuthenticatorMetadata
}

func NewRegistrationService(params WebauthnServiceCreateParams) RegistrationService {

	return &registrationService{
		WebauthnService{
			BaseService: &BaseService{
				logger:              params.Ctx.Logger(),
				tenant:              params.Tenant,
				credentialPersister: params.CredentialPersister,
			},

			webauthnClient: params.WebauthnClient,
			generator:      params.Generator,

			userPersister:        params.UserPersister,
			sessionDataPersister: params.SessionPersister,
		},
		params.AuthenticatorMetadata,
	}
}

func (rs *registrationService) Initialize(user *models.WebauthnUser) (*protocol.CredentialCreation, string, error) {
	internalUser, err := rs.createOrUpdateUser(*user)
	if err != nil {
		return nil, user.UserID, err
	}

	t := true
	credentialCreation, sessionData, err := rs.webauthnClient.BeginRegistration(
		internalUser,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			RequireResidentKey: &t,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   rs.tenant.Config.WebauthnConfig.UserVerification,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		return nil, internalUser.UserId, err
	}

	err = rs.sessionDataPersister.Create(*intern.WebauthnSessionDataToModel(sessionData, rs.tenant.ID, models.WebauthnOperationRegistration))
	if err != nil {
		return nil, internalUser.UserId, err
	}

	return credentialCreation, internalUser.UserId, nil
}
func (rs *registrationService) createOrUpdateUser(user models.WebauthnUser) (*intern.WebauthnUser, error) {
	dbUser, err := rs.getDbUser(user.UserID)
	user.TenantID = rs.tenant.ID

	if err != nil {
		rs.logger.Error(err)
		return nil, err
	}

	if dbUser == nil {
		rs.logger.Debugf("Creating user: %v", user)
		err = rs.userPersister.Create(&user)
	} else {
		rs.logger.Debugf("Updating user: %v", user)
		err = rs.updateUser(dbUser, &user)
	}

	if err != nil {
		rs.logger.Error(err)
		return nil, err
	}

	return intern.NewWebauthnUser(user), err
}

func (rs *registrationService) getDbUser(userId string) (*models.WebauthnUser, error) {
	dbUser, err := rs.userPersister.GetByUserId(userId, rs.tenant.ID)

	if err != nil {
		rs.logger.Error(err)
		return nil, err
	}

	if dbUser == nil {
		return nil, nil
	}

	return dbUser, nil
}

func (rs *registrationService) updateUser(dbUser *models.WebauthnUser, newUser *models.WebauthnUser) error {
	dbUser.Name = newUser.Name
	dbUser.DisplayName = newUser.DisplayName
	dbUser.Icon = newUser.Icon
	dbUser.UpdatedAt = time.Now()

	err := rs.userPersister.Update(dbUser)
	if err != nil {
		rs.logger.Error(err)
		return err
	}

	return nil
}

func (rs *registrationService) Finalize(req *protocol.ParsedCredentialCreationData) (string, *string, error) {
	dbUser, dbSessionData, err := rs.geDbtUserAndSessionFromRequest(req)
	if err != nil {
		if dbSessionData != nil {
			return "", &dbSessionData.UserId, err
		}

		return "", nil, err
	}

	credential, err := rs.createCredential(dbUser, dbSessionData, req)
	if err != nil {
		return "", &dbSessionData.UserId, err
	}

	err = rs.sessionDataPersister.Delete(*dbSessionData)
	if err != nil {
		rs.logger.Warnf("failed to delete attestation session data: %w", err)
	}

	token, err := rs.generator.Generate(dbUser.UserID, credential.ID)
	if err != nil {
		rs.logger.Error(err)
		return "", &dbUser.UserID, err
	}

	return token, &dbUser.UserID, nil
}

func (rs *registrationService) geDbtUserAndSessionFromRequest(req *protocol.ParsedCredentialCreationData) (*models.WebauthnUser, *models.WebauthnSessionData, error) {
	_, sessionData, err := rs.getSessionByChallenge(req.Response.CollectedClientData.Challenge, models.WebauthnOperationRegistration)
	if err != nil {
		rs.logger.Error(err)
		return nil, nil, err
	}

	dbUser, err := rs.getDbUser(sessionData.UserId)
	if err != nil {
		rs.logger.Error(err)
		return nil, sessionData, err
	}

	if dbUser == nil {
		return nil, sessionData, echo.NewHTTPError(http.StatusNotFound, "user not found")
	}

	return dbUser, sessionData, nil
}

func (rs *registrationService) createCredential(dbUser *models.WebauthnUser, session *models.WebauthnSessionData, req *protocol.ParsedCredentialCreationData) (*models.WebauthnCredential, error) {
	credential, err := rs.webauthnClient.CreateCredential(intern.NewWebauthnUser(*dbUser), *intern.WebauthnSessionDataFromModel(session), req)
	if err != nil {
		rs.logger.Error(err)

		errorMessage := "failed to validate attestation"
		errorStatus := http.StatusBadRequest
		// Safari currently (v. 16.2) does not provide a UI in case of a (registration) ceremony
		// being performed with an authenticator NOT protected by e.g. a PIN. While Chromium based browsers do offer
		// a UI guiding through the setup of a PIN, Safari simply performs the ceremony without then setting the UV
		// flag even if it is required. In order to provide an appropriate error message to the frontend/user, we
		// need to return an error response distinguishable from other error cases. We use a dedicated/separate HTTP
		// status code because it seemed a bit more robust than forcing the frontend to check on a matching
		// (sub-)string in the error message in order to properly display the error.
		var perr *protocol.Error
		if errors.As(err, &perr) && perr.Type == protocol.ErrVerification.Type && strings.Contains(perr.DevInfo, "User verification") {
			errorMessage = fmt.Sprintf("%s: %s: %s", errorMessage, perr.Details, perr.DevInfo)
			errorStatus = http.StatusUnprocessableEntity
		}

		return nil, echo.NewHTTPError(errorStatus, errorMessage).SetInternal(err)
	}

	flags := req.Response.AttestationObject.AuthData.Flags
	dbCredential := intern.WebauthnCredentialToModel(
		credential,
		session.UserId,
		dbUser.ID,
		flags.HasBackupEligible(),
		flags.HasBackupState(),
		rs.AuthenticatorMetadata,
	)

	err = rs.credentialPersister.Create(dbCredential)
	if err != nil {
		rs.logger.Error(err)
		return nil, err
	}

	return dbCredential, nil
}
