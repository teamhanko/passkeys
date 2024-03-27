package handler

import (
	"crypto/sha256"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/api/dto/response"
	"github.com/teamhanko/passkey-server/api/helper"
	"github.com/teamhanko/passkey-server/api/services"
	auditlog "github.com/teamhanko/passkey-server/audit_log"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
	"net/http"
)

type transactionHandler struct {
	*webauthnHandler
}

func NewTransactionHandler(persister persistence.Persister) WebauthnHandler {
	webauthnHandler := newWebAuthnHandler(persister, false)

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
		return err
	}

	return t.persister.GetConnection().Transaction(func(tx *pop.Connection) error {
		sessionDataPersister := t.persister.GetWebauthnSessionDataPersister(tx)
		webauthnUserPersister := t.persister.GetWebauthnUserPersister(tx)
		transactionPersister := t.persister.GetTransactionPersister(tx)

		service := services.NewTransactionService(services.TransactionServiceCreateParams{
			WebauthnServiceCreateParams: &services.WebauthnServiceCreateParams{
				Ctx:              ctx,
				Tenant:           *h.Tenant,
				WebauthnClient:   *h.WebauthnClient,
				UserPersister:    webauthnUserPersister,
				SessionPersister: sessionDataPersister,
			},
			TransactionPersister: transactionPersister,
		})

		credentialAssertion, err := service.Initialize(dto.UserId, transactionModel)
		err = t.handleError(h.AuditLog, models.AuditLogWebAuthnTransactionInitFailed, tx, ctx, &dto.UserId, transactionModel, err)
		if err != nil {
			return err
		}

		auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnTransactionInitSucceeded, &dto.UserId, transactionModel, nil)
		if auditErr != nil {
			ctx.Logger().Error(auditErr)
			return fmt.Errorf(auditlog.CreationFailureFormat, auditErr)
		}

		return ctx.JSON(http.StatusOK, credentialAssertion)
	})

}

func (t *transactionHandler) Finish(ctx echo.Context) error {
	parsedRequest, err := protocol.ParseCredentialRequestResponse(ctx.Request())
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to finish transaction").SetInternal(err)
	}

	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return t.persister.Transaction(func(tx *pop.Connection) error {
		sessionDataPersister := t.persister.GetWebauthnSessionDataPersister(tx)
		webauthnUserPersister := t.persister.GetWebauthnUserPersister(tx)
		credentialPersister := t.persister.GetWebauthnCredentialPersister(tx)
		transactionPersister := t.persister.GetTransactionPersister(tx)

		service := services.NewTransactionService(services.TransactionServiceCreateParams{
			WebauthnServiceCreateParams: &services.WebauthnServiceCreateParams{
				Ctx:                 ctx,
				Tenant:              *h.Tenant,
				WebauthnClient:      *h.WebauthnClient,
				UserPersister:       webauthnUserPersister,
				SessionPersister:    sessionDataPersister,
				CredentialPersister: credentialPersister,
				Generator:           h.Generator,
			},
			TransactionPersister: transactionPersister,
		})

		token, userHandle, transaction, err := service.Finalize(parsedRequest)
		err = t.handleError(h.AuditLog, models.AuditLogWebAuthnTransactionFinalFailed, tx, ctx, &userHandle, transaction, err)
		if err != nil {
			return err
		}

		auditErr := h.AuditLog.CreateWithConnection(tx, models.AuditLogWebAuthnTransactionFinalSucceeded, &userHandle, transaction, nil)
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

	if sessionData != nil && sessionData.Operation != models.WebauthnOperationTransaction {
		sessionData = nil
	}

	if sessionData == nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "received challenge does not match with any stored one")
	}

	return sessionData, nil
}
