package persisters

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type TransactionPersister interface {
	Create(transaction *models.Transaction) error
	ListByUserId(userId uuid.UUID, tenantId uuid.UUID) (*models.Transactions, error)
	GetByUserId(userId uuid.UUID, tenantId uuid.UUID) (*models.Transaction, error)
	GetByChallenge(challenge string, tenantId uuid.UUID) (*models.Transaction, error)
}

type transactionPersister struct {
	database *pop.Connection
}

func NewTransactionPersister(database *pop.Connection) TransactionPersister {
	return &transactionPersister{
		database: database,
	}
}

func (p *transactionPersister) Create(transaction *models.Transaction) error {
	vErr, err := p.database.ValidateAndCreate(transaction)
	if err != nil {
		return fmt.Errorf("failed to store transaction: %w", err)
	}
	if vErr != nil && vErr.HasAny() {
		return fmt.Errorf("transaction object validation failed: %w", vErr)
	}

	return nil
}

func (p *transactionPersister) GetByUserId(userId uuid.UUID, tenantId uuid.UUID) (*models.Transaction, error) {
	transaction := models.Transaction{}
	err := p.database.Eager().Where("webauthn_user_id = ? AND tenant_id = ?", userId, tenantId).First(&transaction)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction by user id: %w", err)
	}

	return &transaction, nil
}

func (p *transactionPersister) ListByUserId(userId uuid.UUID, tenantId uuid.UUID) (*models.Transactions, error) {
	transactions := models.Transactions{}
	err := p.database.Eager().Where("webauthn_user_id = ? AND tenant_id = ?", userId, tenantId).All(&transactions)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list transactions by user id: %w", err)
	}

	return &transactions, nil
}

func (p *transactionPersister) GetByChallenge(challenge string, tenantId uuid.UUID) (*models.Transaction, error) {
	transaction := models.Transaction{}
	err := p.database.Eager().Where("challenge = ? AND tenant_id = ?", challenge, tenantId).First(&transaction)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction by user id: %w", err)
	}

	return &transaction, nil
}
