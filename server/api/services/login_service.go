package services

import (
	"encoding/base64"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/intern"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
)

type LoginService interface {
	Initialize() (*protocol.CredentialAssertion, error)
	Finalize(req *protocol.ParsedCredentialAssertionData) (string, string, error)
}

type loginService struct {
	WebauthnService
	userId *string
}

func NewLoginService(params WebauthnServiceCreateParams) LoginService {

	return &loginService{
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
			useMFA:               params.UseMFA,
		},
		params.UserId,
	}
}

func (ls *loginService) Initialize() (*protocol.CredentialAssertion, error) {
	var credentialAssertion *protocol.CredentialAssertion
	var sessionData *webauthn.SessionData
	var err error
	isDiscoverable := true

	if ls.userId != nil {
		user, err := ls.getWebauthnUserByUserHandle(*ls.userId)
		if err != nil {
			ls.logger.Error(err)

			return nil, echo.NewHTTPError(http.StatusNotFound, err)
		}

		credentialAssertion, sessionData, err = ls.webauthnClient.BeginLogin(user)
		if err != nil {
			ls.logger.Error(err)
			return nil, echo.NewHTTPError(
				http.StatusInternalServerError,
				fmt.Errorf("failed to create webauthn assertion options for login: %w", err),
			)
		}

		isDiscoverable = false
	} else {
		credentialAssertion, sessionData, err = ls.webauthnClient.BeginDiscoverableLogin()

		if err != nil {
			ls.logger.Error(err)
			return nil, echo.NewHTTPError(
				http.StatusInternalServerError,
				fmt.Errorf("failed to create webauthn assertion options for discoverable login: %w", err),
			)
		}
	}

	err = ls.sessionDataPersister.Create(*intern.WebauthnSessionDataToModel(sessionData, ls.tenant.ID, models.WebauthnOperationAuthentication, isDiscoverable))
	if err != nil {
		ls.logger.Error(err)
		return nil, err
	}

	// Remove all transports, because of a bug in android and windows where the internal authenticator gets triggered,
	// when the transports array contains the type 'internal' although the credential is not available on the device.
	for i := range credentialAssertion.Response.AllowedCredentials {
		credentialAssertion.Response.AllowedCredentials[i].Transport = nil
	}

	return credentialAssertion, nil
}

func (ls *loginService) Finalize(req *protocol.ParsedCredentialAssertionData) (string, string, error) {
	// backward compatibility
	userHandle := ls.convertUserHandle(req.Response.UserHandle)
	sessionData, dbSessionData, err := ls.getSessionByChallenge(req.Response.CollectedClientData.Challenge, models.WebauthnOperationAuthentication)
	if err != nil {
		return "", userHandle, echo.NewHTTPError(http.StatusUnauthorized, "failed to get session data").SetInternal(err)
	}

	// when using MFA or session was initialized for a non-discoverable cred
	if ls.useMFA || !dbSessionData.IsDiscoverable {
		userHandle = ls.convertUserHandle(sessionData.UserID)
	}

	req.Response.UserHandle = []byte(userHandle)
	webauthnUser, err := ls.getWebauthnUserByUserHandle(userHandle)
	if err != nil {
		return "", userHandle, echo.NewHTTPError(http.StatusUnauthorized, "failed to get user by user handle").SetInternal(err)
	}

	var credential *webauthn.Credential
	if dbSessionData.IsDiscoverable {
		credential, err = ls.webauthnClient.ValidateDiscoverableLogin(func(rawID, userHandle []byte) (user webauthn.User, err error) {
			return webauthnUser, nil
		}, *sessionData, req)
	} else {
		credential, err = ls.webauthnClient.ValidateLogin(webauthnUser, *sessionData, req)
	}

	if err != nil {
		ls.logger.Error(err)
		return "", userHandle, echo.NewHTTPError(http.StatusUnauthorized, "failed to validate assertion").SetInternal(err)
	}
	credentialId := base64.RawURLEncoding.EncodeToString(credential.ID)

	dbCredential := webauthnUser.FindCredentialById(credentialId)
	if !ls.useMFA && dbCredential.IsMFA {
		return "", userHandle, echo.NewHTTPError(http.StatusBadRequest, "MFA credentials are not usable for normal login")
	}

	err = ls.updateCredentialForUser(dbCredential, req.Response.AuthenticatorData.Flags)
	if err != nil {
		return "", userHandle, err
	}

	err = ls.sessionDataPersister.Delete(*dbSessionData)
	if err != nil {
		ls.logger.Error(err)
		return "", userHandle, fmt.Errorf("failed to delete assertion session data: %w", err)
	}

	token, err := ls.createUserCredentialToken(webauthnUser.UserId, credentialId)
	if err != nil {
		ls.logger.Error(err)
		return "", userHandle, err
	}

	return token, userHandle, nil
}
