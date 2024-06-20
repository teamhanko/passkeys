package services

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/intern"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
	"net/http"
)

type TransactionService interface {
	Initialize(userId string, transaction *models.Transaction) (*protocol.CredentialAssertion, error)
	Finalize(req *protocol.ParsedCredentialAssertionData) (string, string, *models.Transaction, error)
}

type TransactionServiceCreateParams struct {
	*WebauthnServiceCreateParams

	TransactionPersister persisters.TransactionPersister
}

type transactionService struct {
	*WebauthnService

	transactionPersister persisters.TransactionPersister
}

func NewTransactionService(params TransactionServiceCreateParams) TransactionService {
	return &transactionService{
		WebauthnService: &WebauthnService{
			BaseService: &BaseService{
				logger:              params.Ctx.Logger(),
				tenant:              params.Tenant,
				credentialPersister: params.CredentialPersister,
			},

			webauthnClient: params.WebauthnClient,
			generator:      params.Generator,

			userPersister:        params.UserPersister,
			sessionDataPersister: params.SessionPersister,

			useMFA: params.UseMFA,
		},
		transactionPersister: params.TransactionPersister,
	}
}

func (ts *transactionService) Initialize(userId string, transaction *models.Transaction) (*protocol.CredentialAssertion, error) {
	webauthnUser, err := ts.userPersister.GetByUserId(userId, ts.tenant.ID)
	if err != nil {
		ts.logger.Error(err)
		return nil, echo.NewHTTPError(http.StatusNotFound, "unable to find user")
	}

	if webauthnUser == nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, "unable to find user")
	}

	foundTransaction, err := ts.transactionPersister.GetByIdentifier(transaction.Identifier, ts.tenant.ID)
	if err != nil {
		ts.logger.Error(err)
		return nil, echo.NewHTTPError(http.StatusInternalServerError, "unable to search for transaction")
	}

	if foundTransaction != nil && len(*foundTransaction) > 0 {
		ts.logger.Error("transaction already exists")
		return nil, echo.NewHTTPError(http.StatusConflict, "transaction already exists")
	}

	// check for better error handling as BeginLogin can throw a BadRequestError AND normal errors (but same type)
	if len(webauthnUser.WebauthnCredentials) == 0 {
		return nil, echo.NewHTTPError(
			http.StatusBadRequest,
			fmt.Errorf("user has no suitable credentials for this operation"),
		)
	}

	credentialAssertion, sessionData, err := ts.webauthnClient.BeginLogin(
		intern.NewWebauthnUser(*webauthnUser, ts.useMFA),
		ts.withTransaction(transaction.Identifier, transaction.Data),
	)
	if err != nil {
		return nil, echo.NewHTTPError(
			http.StatusInternalServerError,
			fmt.Errorf("failed to create webauthn assertion options for transaction: %w", err),
		)
	}

	// workaround: go-webauthn changes only the assertion challenge when giving LoginOptions
	sessionData.Challenge = credentialAssertion.Response.Challenge.String()
	transaction.Challenge = sessionData.Challenge
	transaction.WebauthnUserID = webauthnUser.ID
	transaction.TenantID = ts.tenant.ID

	err = ts.transactionPersister.Create(transaction)
	if err != nil {
		ts.logger.Error(err)
		return nil, err
	}

	err = ts.sessionDataPersister.Create(*intern.WebauthnSessionDataToModel(sessionData, ts.tenant.ID, models.WebauthnOperationTransaction, false))
	if err != nil {
		ts.logger.Error(err)
		return nil, err
	}

	// Remove all transports, because of a bug in android and windows where the internal authenticator gets triggered,
	// when the transports array contains the type 'internal' although the credential is not available on the device.
	for i := range credentialAssertion.Response.AllowedCredentials {
		credentialAssertion.Response.AllowedCredentials[i].Transport = nil
	}

	return credentialAssertion, nil
}

func (ts *transactionService) withTransaction(transactionId string, transactionDataJson string) webauthn.LoginOption {
	return func(options *protocol.PublicKeyCredentialRequestOptions) {
		transaction := []byte(transactionId)
		transactionData := []byte(transactionDataJson)

		transaction = append(transaction, transactionData[:]...)

		transactionHash := sha256.Sum256(transaction)
		options.Challenge = append(options.Challenge, transactionHash[:]...)
	}
}

func (ts *transactionService) Finalize(req *protocol.ParsedCredentialAssertionData) (string, string, *models.Transaction, error) {
	// backward compatibility
	userHandle := ts.convertUserHandle(req.Response.UserHandle)
	req.Response.UserHandle = []byte(userHandle)

	challenge := req.Response.CollectedClientData.Challenge

	transaction, err := ts.getTransactionByChallenge(challenge)
	if err != nil {
		return "", userHandle, nil, echo.NewHTTPError(http.StatusUnauthorized, "failed to get transaction data").SetInternal(err)
	}

	sessionData, dbSessionData, err := ts.getSessionByChallenge(req.Response.CollectedClientData.Challenge, models.WebauthnOperationTransaction)
	if err != nil {
		return "", userHandle, transaction, echo.NewHTTPError(http.StatusUnauthorized, "failed to get session data").SetInternal(err)
	}

	webauthnUser, err := ts.getWebauthnUserByUserHandle(userHandle)
	if err != nil {
		return "", userHandle, transaction, echo.NewHTTPError(http.StatusUnauthorized, "failed to get user by user handle").SetInternal(err)
	}

	credential, err := ts.webauthnClient.ValidateLogin(webauthnUser, *sessionData, req)
	if err != nil {
		ts.logger.Error(err)
		return "", userHandle, transaction, echo.NewHTTPError(http.StatusUnauthorized, "failed to validate assertion").SetInternal(err)
	}
	credentialId := base64.RawURLEncoding.EncodeToString(credential.ID)

	dbCredential := webauthnUser.FindCredentialById(credentialId)
	if !ts.useMFA && dbCredential.IsMFA {
		return "", userHandle, transaction, echo.NewHTTPError(http.StatusBadRequest, "MFA credentials are not usable for transactions")
	}

	err = ts.updateCredentialForUser(dbCredential, req.Response.AuthenticatorData.Flags)
	if err != nil {
		return "", userHandle, transaction, err
	}

	err = ts.sessionDataPersister.Delete(*dbSessionData)
	if err != nil {
		ts.logger.Error(err)
		return "", userHandle, transaction, fmt.Errorf("failed to delete assertion session data: %w", err)
	}

	token, err := ts.generator.GenerateForTransaction(webauthnUser.UserId, base64.RawURLEncoding.EncodeToString(credential.ID), transaction.Identifier)
	if err != nil {
		ts.logger.Error(err)
		return "", userHandle, transaction, fmt.Errorf("failed to generate jwt: %w", err)
	}

	return token, userHandle, transaction, nil
}

func (ts *transactionService) getTransactionByChallenge(challenge string) (*models.Transaction, error) {
	transaction, err := ts.transactionPersister.GetByChallenge(challenge, ts.tenant.ID)
	if err != nil {
		ts.logger.Error(err)
		return nil, fmt.Errorf("failed to get transaction data: %w", err)
	}

	if transaction == nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, "no transaction found for this challenge")
	}

	return transaction, nil
}
