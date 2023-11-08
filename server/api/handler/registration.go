package handler

import (
	"errors"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/intern"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/api/dto/response"
	"github.com/teamhanko/passkey-server/crypto/jwt"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
	"net/http"
	"strings"
)

type registrationHandler struct {
	*webauthnHandler
}

func NewRegistrationHandler(persister persistence.Persister) (WebauthnHandler, error) {
	webauthnHandler, err := newWebAuthnHandler(persister)
	if err != nil {
		return nil, err
	}

	return &registrationHandler{
		webauthnHandler,
	}, nil
}

func (r *registrationHandler) Init(ctx echo.Context) error {
	dto, err := BindAndValidateRequest[request.InitRegistrationDto](ctx)
	if err != nil {
		return err
	}

	webauthnUser, err := models.FromRegistrationDto(dto)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	h, err := GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return r.persister.Transaction(func(tx *pop.Connection) error {
		webauthnUserPersister := r.persister.GetWebauthnUserPersister(tx)
		webauthnSessionPersister := r.persister.GetWebauthnSessionDataPersister(tx)

		webauthnUser.Tenant = h.tenant
		internalUserDto, _, err := r.GetWebauthnUser(webauthnUser.UserID, webauthnUser.Tenant.ID, webauthnUserPersister)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}

		if internalUserDto == nil {
			err = webauthnUserPersister.Create(webauthnUser)
			if err != nil {
				ctx.Logger().Error(err)
				return err
			}

			internalUserDto = intern.NewWebauthnUser(*webauthnUser)
		}

		t := true
		options, sessionData, err := h.webauthn.BeginRegistration(
			internalUserDto,
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				RequireResidentKey: &t,
				ResidentKey:        protocol.ResidentKeyRequirementRequired,
				UserVerification:   h.config.WebauthnConfig.UserVerification,
			}),
			webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
			// don't set the excludeCredentials list, so an already registered device can be re-registered
		)

		err = webauthnSessionPersister.Create(*intern.WebauthnSessionDataToModel(sessionData, h.tenant.ID, models.WebauthnOperationRegistration))
		if err != nil {
			ctx.Logger().Error(err)
			return fmt.Errorf("failed to create session data: %w", err)
		}

		err = h.auditLog.CreateWithConnection(tx, ctx, h.tenant, models.AuditLogWebAuthnRegistrationInitSucceeded, &webauthnUser.UserID, nil)
		if err != nil {
			ctx.Logger().Error(err)
			return fmt.Errorf("failed to create audit log: %w", err)
		}

		return ctx.JSON(http.StatusOK, options)
	})
}

func (r *registrationHandler) Finish(ctx echo.Context) error {
	parsedRequest, err := protocol.ParseCredentialCreationResponse(ctx.Request())
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to parse credential creation response").SetInternal(err)
	}

	h, err := GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return r.persister.Transaction(func(tx *pop.Connection) error {
		sessionDataPersister := r.persister.GetWebauthnSessionDataPersister(tx)
		webauthnUserPersister := r.persister.GetWebauthnUserPersister(tx)

		sessionData, err := r.getSessionByChallenge(parsedRequest.Response.CollectedClientData.Challenge, h.tenant.ID, sessionDataPersister)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}

		webauthnUser, userModel, err := r.GetWebauthnUser(sessionData.UserId, h.tenant.ID, webauthnUserPersister)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}

		if webauthnUser == nil || userModel == nil {
			return echo.NewHTTPError(http.StatusNotFound, "user not found")
		}

		credential, err := h.webauthn.CreateCredential(webauthnUser, *intern.WebauthnSessionDataFromModel(sessionData), parsedRequest)
		if err != nil {
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
			ctx.Logger().Error(perr)
			if errors.As(err, &perr) && perr.Type == protocol.ErrVerification.Type && strings.Contains(perr.DevInfo, "User verification") {
				errorMessage = fmt.Sprintf("%s: %s: %s", errorMessage, perr.Details, perr.DevInfo)
				errorStatus = http.StatusUnprocessableEntity
			}

			ctx.Logger().Error(err)
			return echo.NewHTTPError(errorStatus, errorMessage).SetInternal(err)
		}

		flags := parsedRequest.Response.AttestationObject.AuthData.Flags
		model := intern.WebauthnCredentialToModel(credential, sessionData.UserId, userModel.ID, flags.HasBackupEligible(), flags.HasBackupState())
		err = r.persister.GetWebauthnCredentialPersister(tx).Create(model)
		if err != nil {
			ctx.Logger().Error(err)
			return fmt.Errorf("failed to store webauthn credential: %w", err)
		}

		err = sessionDataPersister.Delete(*sessionData)
		if err != nil {
			ctx.Logger().Errorf("failed to delete attestation session data: %w", err)
		}

		generator := ctx.Get("jwt_generator").(jwt.Generator)
		token, err := generator.Generate(webauthnUser.UserId, model.ID)
		if err != nil {
			ctx.Logger().Error(err)
			return fmt.Errorf("failed to generate jwt: %w", err)
		}

		return ctx.JSON(http.StatusOK, &response.TokenDto{Token: token})
	})
}

func (r *registrationHandler) getSessionByChallenge(challenge string, tenantId uuid.UUID, persister persisters.WebauthnSessionDataPersister) (*models.WebauthnSessionData, error) {
	sessionData, err := persister.GetByChallenge(challenge, tenantId)
	if err != nil {
		return nil, err
	}

	if sessionData == nil || sessionData.Operation != models.WebauthnOperationRegistration {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "received challenge does not match with any stored one")
	}

	return sessionData, nil
}

func (r *registrationHandler) GetWebauthnUser(userId string, tenantId uuid.UUID, persister persisters.WebauthnUserPersister) (*intern.WebauthnUser, *models.WebauthnUser, error) {
	user, err := persister.GetByUserId(userId, tenantId)
	if err != nil {
		return nil, nil, err
	}

	if user == nil {
		return nil, nil, nil
	}

	return intern.NewWebauthnUser(*user), user, nil
}
