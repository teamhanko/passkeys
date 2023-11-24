package auditlog

import (
	"fmt"
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	zeroLog "github.com/rs/zerolog"
	zeroLogger "github.com/rs/zerolog/log"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
	"os"
	"strconv"
	"time"
)

type Logger interface {
	Create(models.AuditLogType, *string, *models.Transaction, error) error
	CreateWithConnection(*pop.Connection, models.AuditLogType, *string, *models.Transaction, error) error
}

type logger struct {
	persister             persistence.Persister
	storageEnabled        bool
	logger                zeroLog.Logger
	consoleLoggingEnabled bool
	tenant                *models.Tenant
	ctx                   echo.Context
}

const (
	CreationFailureFormat = "failed to create audit log: %w"
)

func NewLogger(persister persistence.Persister, cfg models.AuditLogConfig, ctx echo.Context, tenant *models.Tenant) Logger {
	var loggerOutput *os.File = nil
	switch cfg.OutputStream {
	case config.OutputStreamStdOut:
		loggerOutput = os.Stdout
	case config.OutputStreamStdErr:
		loggerOutput = os.Stderr
	default:
		loggerOutput = os.Stdout
	}

	return &logger{
		persister:             persister,
		storageEnabled:        cfg.StorageEnabled,
		logger:                zeroLog.New(loggerOutput),
		consoleLoggingEnabled: cfg.ConsoleEnabled,
		ctx:                   ctx,
		tenant:                tenant,
	}
}

func (l *logger) Create(auditLogType models.AuditLogType, user *string, transaction *models.Transaction, logError error) error {
	return l.CreateWithConnection(l.persister.GetConnection(), auditLogType, user, transaction, logError)
}

func (l *logger) CreateWithConnection(tx *pop.Connection, auditLogType models.AuditLogType, user *string, transaction *models.Transaction, logError error) error {
	if l.storageEnabled {
		err := l.store(tx, auditLogType, user, transaction, logError)
		if err != nil {
			return err
		}
	}

	if l.consoleLoggingEnabled {
		l.logToConsole(auditLogType, user, transaction, logError)
	}

	return nil
}

func (l *logger) store(tx *pop.Connection, auditLogType models.AuditLogType, user *string, transaction *models.Transaction, logError error) error {
	id, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("failed to create id: %w", err)
	}

	al := models.AuditLog{
		ID:                id,
		Tenant:            l.tenant,
		Type:              auditLogType,
		Error:             nil,
		MetaHttpRequestId: l.ctx.Response().Header().Get(echo.HeaderXRequestID),
		MetaUserAgent:     l.ctx.Request().UserAgent(),
		MetaSourceIp:      l.ctx.RealIP(),
		ActorUserId:       nil,
		TransactionId:     nil,
	}

	if user != nil {
		al.ActorUserId = user
	}

	if transaction != nil {
		al.TransactionId = &transaction.Identifier
	}

	if logError != nil {
		// check if error is not nil, because else the string (formatted with fmt.Sprintf) would not be empty but look like this: `%!s(<nil>)`
		tmp := fmt.Sprintf("%s", logError)
		al.Error = &tmp
	}

	return l.persister.GetAuditLogPersister(tx).Create(al)
}

func (l *logger) logToConsole(auditLogType models.AuditLogType, user *string, transaction *models.Transaction, logError error) {
	now := time.Now()
	loggerEvent := zeroLogger.Log().
		Str("audience", "audit").
		Str("type", string(auditLogType)).
		AnErr("error", logError).
		Str("tenant", l.tenant.ID.String()).
		Str("http_request_id", l.ctx.Response().Header().Get(echo.HeaderXRequestID)).
		Str("source_ip", l.ctx.RealIP()).
		Str("user_agent", l.ctx.Request().UserAgent()).
		Str("time", now.Format(time.RFC3339Nano)).
		Str("time_unix", strconv.FormatInt(now.Unix(), 10))

	if user != nil {
		loggerEvent.Str("user_id", *user)
	}

	if transaction != nil {
		loggerEvent.Str("transaction_id", transaction.Identifier)
	}

	loggerEvent.Send()
}
