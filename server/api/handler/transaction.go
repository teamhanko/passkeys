package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/intern"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/api/dto/response"
	"github.com/teamhanko/passkey-server/api/helper"
	auditlog "github.com/teamhanko/passkey-server/audit_log"
	"github.com/teamhanko/passkey-server/crypto/jwt"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
	"net/http"
	"time"
)

type transactionHandler struct {
	*webauthnHandler
}

func NewTransactionHandler(persister persistence.Persister) WebauthnHandler {
	webauthnHandler := newWebAuthnHandler(persister)

	return &transactionHandler{webauthnHandler}
}

func (t *transactionHandler) Init(ctx echo.Context) error {
	dto, err := BindAndValidateRequest[request.InitTransactionDto](ctx)
	if err != nil {
		return err
	}

	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	transactionModel, err := dto.ToModel()
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, "unable to process request")
	}

	return t.persister.GetConnection().Transaction(func(tx *pop.Connection) error {
		webauthnUser, err := t.persister.GetWebauthnUserPersister(tx).GetByUserId(dto.UserId, h.Tenant.ID)
		if err != nil {
			ctx.Logger().Error(err)
			return echo.NewHTTPError(http.StatusNotFound, "Unable to find user")
		}

		if webauthnUser == nil {
			return echo.NewHTTPError(http.StatusNotFound, "Unable to find user")
		}

		assertion, sessionData, err := h.Webauthn.BeginLogin(
			intern.NewWebauthnUser(*webauthnUser),
			webauthn.WithUserVerification(h.Config.WebauthnConfig.UserVerification),
			t.withTransaction(transactionModel.Identifier, transactionModel.Data),
		)
		if err != nil {
			auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnTransactionInitFailed, &webauthnUser.UserID, transactionModel, err)
			if auditErr != nil {
				ctx.Logger().Error(auditErr)
				return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
			}

			ctx.Logger().Error(err)
			return echo.NewHTTPError(
				http.StatusBadRequest,
				fmt.Errorf("failed to create webauthn assertion options for transaction: %w", err),
			)
		}

		// workaround: go-webauthn changes only the assertion challenge when giving LoginOptions
		sessionData.Challenge = assertion.Response.Challenge.String()

		ctx.Logger().Printf("SessionData Challenge: %s", sessionData.Challenge)
		ctx.Logger().Printf("Assertion Challenge: %s", assertion.Response.Challenge)

		transactionModel.Challenge = sessionData.Challenge
		transactionModel.WebauthnUserID = webauthnUser.ID
		transactionModel.TenantID = h.Tenant.ID

		err = t.persister.GetTransactionPersister(tx).Create(transactionModel)
		if err != nil {
			auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnAuthenticationInitFailed, &webauthnUser.UserID, transactionModel, err)
			if auditErr != nil {
				ctx.Logger().Error(auditErr)
				return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
			}

			ctx.Logger().Error(err)
			return fmt.Errorf("failed to store webauthn transaction data: %w", err)
		}

		err = t.persister.GetWebauthnSessionDataPersister(tx).Create(*intern.WebauthnSessionDataToModel(sessionData, h.Tenant.ID, models.WebauthnOperationAuthentication))
		if err != nil {
			auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnAuthenticationInitFailed, &webauthnUser.UserID, transactionModel, err)
			if auditErr != nil {
				ctx.Logger().Error(auditErr)
				return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
			}

			ctx.Logger().Error(err)
			return fmt.Errorf("failed to store webauthn assertion session data: %w", err)
		}

		// Remove all transports, because of a bug in android and windows where the internal authenticator gets triggered,
		// when the transports array contains the type 'internal' although the credential is not available on the device.
		for i := range assertion.Response.AllowedCredentials {
			assertion.Response.AllowedCredentials[i].Transport = nil
		}

		auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnTransactionInitSucceeded, &webauthnUser.UserID, transactionModel, nil)
		if auditErr != nil {
			ctx.Logger().Error(auditErr)
			return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
		}

		return ctx.JSON(http.StatusOK, assertion)
	})

}

func (t *transactionHandler) Finish(ctx echo.Context) error {
	parsedRequest, err := protocol.ParseCredentialRequestResponse(ctx.Request())
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return t.persister.Transaction(func(tx *pop.Connection) error {
		ctx.Logger().Printf("Response Challenge: %s", parsedRequest.Response.CollectedClientData.Challenge)

		challenge := parsedRequest.Response.CollectedClientData.Challenge

		sessionDataPersister := t.persister.GetWebauthnSessionDataPersister(tx)
		webauthnUserPersister := t.persister.GetWebauthnUserPersister(tx)
		credentialPersister := t.persister.GetWebauthnCredentialPersister(tx)
		transactionPersister := t.persister.GetTransactionPersister(tx)

		userHandle := t.convertUserHandle(parsedRequest.Response.UserHandle)
		// backward compatibility
		parsedRequest.Response.UserHandle = []byte(userHandle)

		transaction, err := t.getTransactionByChallenge(challenge, transactionPersister, h.Tenant.ID)
		if err != nil {
			auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnTransactionFinalFailed, &userHandle, transaction, err)
			if auditErr != nil {
				ctx.Logger().Error(auditErr)
				return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
			}

			ctx.Logger().Error(err)
			return echo.NewHTTPError(http.StatusUnauthorized, "failed to get transaction data").SetInternal(err)
		}

		sessionData, err := t.getSessionDataByChallenge(challenge, sessionDataPersister, h.Tenant.ID)
		if err != nil {
			auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnTransactionFinalFailed, &userHandle, transaction, err)
			if auditErr != nil {
				ctx.Logger().Error(auditErr)
				return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
			}

			ctx.Logger().Error(err)
			return echo.NewHTTPError(http.StatusUnauthorized, "failed to get session data").SetInternal(err)
		}
		sessionDataModel := intern.WebauthnSessionDataFromModel(sessionData)

		webauthnUser, err := t.getWebauthnUserByUserHandle(userHandle, h.Tenant.ID, webauthnUserPersister)
		if err != nil {
			auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnTransactionFinalFailed, &userHandle, transaction, err)
			if auditErr != nil {
				ctx.Logger().Error(auditErr)
				return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
			}

			ctx.Logger().Error(err)
			return echo.NewHTTPError(http.StatusUnauthorized, "failed to get user handle")
		}

		credential, err := h.Webauthn.ValidateLogin(webauthnUser, *sessionDataModel, parsedRequest)
		if err != nil {
			auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnTransactionFinalFailed, &webauthnUser.UserId, transaction, err)
			if auditErr != nil {
				ctx.Logger().Error(auditErr)
				return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
			}

			ctx.Logger().Error(err)
			return echo.NewHTTPError(http.StatusUnauthorized, "failed to validate assertion").SetInternal(err)
		}

		dbCred := webauthnUser.FindCredentialById(base64.RawURLEncoding.EncodeToString(credential.ID))
		if dbCred != nil {
			flags := parsedRequest.Response.AuthenticatorData.Flags
			now := time.Now().UTC()

			dbCred.BackupState = flags.HasBackupState()
			dbCred.BackupEligible = flags.HasBackupEligible()
			dbCred.LastUsedAt = &now
			err = credentialPersister.Update(dbCred)
			if err != nil {
				auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnTransactionFinalFailed, &webauthnUser.UserId, transaction, err)
				if auditErr != nil {
					ctx.Logger().Error(auditErr)
					return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
				}

				ctx.Logger().Error(err)
				return fmt.Errorf("failed to update webauthn credential: %w", err)
			}
		}

		err = sessionDataPersister.Delete(*sessionData)
		if err != nil {
			ctx.Logger().Error(err)
			return fmt.Errorf("failed to delete assertion session data: %w", err)
		}

		generator := ctx.Get("jwt_generator").(jwt.Generator)
		token, err := generator.GenerateForTransaction(webauthnUser.UserId, base64.RawURLEncoding.EncodeToString(credential.ID), transaction.Identifier)
		if err != nil {
			ctx.Logger().Error(err)
			return fmt.Errorf("failed to generate jwt: %w", err)
		}

		auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnTransactionFinalSucceeded, &webauthnUser.UserId, transaction, nil)
		if auditErr != nil {
			ctx.Logger().Error(auditErr)
			return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
		}

		return ctx.JSON(http.StatusOK, &response.TokenDto{Token: token})
	})
}

func (t *transactionHandler) withTransaction(transactionId string, transactionDataJson string) webauthn.LoginOption {
	return func(options *protocol.PublicKeyCredentialRequestOptions) {
		transaction := []byte(transactionId)
		transactionData := []byte(transactionDataJson)

		transaction = append(transaction, transactionData[:]...)

		transactionHash := sha256.Sum256(transaction)
		options.Challenge = append(options.Challenge, transactionHash[:]...)
	}
}

func (t *transactionHandler) getTransactionByChallenge(challenge string, persister persisters.TransactionPersister, tenantId uuid.UUID) (*models.Transaction, error) {
	transaction, err := persister.GetByChallenge(challenge, tenantId)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction data: %w", err)
	}

	if transaction == nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, "no transaction found for this challenge")
	}

	return transaction, nil
}

func (t *transactionHandler) getSessionDataByChallenge(challenge string, persister persisters.WebauthnSessionDataPersister, tenantId uuid.UUID) (*models.WebauthnSessionData, error) {
	sessionData, err := persister.GetByChallenge(challenge, tenantId)
	if err != nil {
		return nil, fmt.Errorf("failed to get webauthn assertion session data: %w", err)
	}

	if sessionData != nil && sessionData.Operation != models.WebauthnOperationAuthentication {
		sessionData = nil
	}

	if sessionData == nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "received challenge does not match with any stored one")
	}

	return sessionData, nil
}

func (t *transactionHandler) getWebauthnUserByUserHandle(userHandle string, tenantId uuid.UUID, persister persisters.WebauthnUserPersister) (*intern.WebauthnUser, error) {
	user, err := persister.GetByUserId(userHandle, tenantId)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	return intern.NewWebauthnUser(*user), nil
}
