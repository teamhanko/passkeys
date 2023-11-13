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
	Create(echo.Context, *models.Tenant, models.AuditLogType, *string, error) error
	CreateWithConnection(*pop.Connection, echo.Context, *models.Tenant, models.AuditLogType, *string, error) error
}

type logger struct {
	persister             persistence.Persister
	storageEnabled        bool
	logger                zeroLog.Logger
	consoleLoggingEnabled bool
}

const (
	CreationFailureFormat = "failed to create audit log: %w"
)

func NewLogger(persister persistence.Persister, cfg models.AuditLogConfig) Logger {
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
	}
}

func (l *logger) Create(context echo.Context, tenant *models.Tenant, auditLogType models.AuditLogType, user *string, logError error) error {
	return l.CreateWithConnection(l.persister.GetConnection(), context, tenant, auditLogType, user, logError)
}

func (l *logger) CreateWithConnection(tx *pop.Connection, context echo.Context, tenant *models.Tenant, auditLogType models.AuditLogType, user *string, logError error) error {
	if l.storageEnabled {
		err := l.store(tx, context, tenant, auditLogType, user, logError)
		if err != nil {
			return err
		}
	}

	if l.consoleLoggingEnabled {
		l.logToConsole(context, tenant, auditLogType, user, logError)
	}

	return nil
}

func (l *logger) store(tx *pop.Connection, context echo.Context, tenant *models.Tenant, auditLogType models.AuditLogType, user *string, logError error) error {
	id, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("failed to create id: %w", err)
	}

	al := models.AuditLog{
		ID:                id,
		Tenant:            tenant,
		Type:              auditLogType,
		Error:             nil,
		MetaHttpRequestId: context.Response().Header().Get(echo.HeaderXRequestID),
		MetaUserAgent:     context.Request().UserAgent(),
		MetaSourceIp:      context.RealIP(),
		ActorUserId:       nil,
	}

	if user != nil {
		al.ActorUserId = user
	}
	if logError != nil {
		// check if error is not nil, because else the string (formatted with fmt.Sprintf) would not be empty but look like this: `%!s(<nil>)`
		tmp := fmt.Sprintf("%s", logError)
		al.Error = &tmp
	}

	return l.persister.GetAuditLogPersister(tx).Create(al)
}

func (l *logger) logToConsole(context echo.Context, tenant *models.Tenant, auditLogType models.AuditLogType, user *string, logError error) {
	now := time.Now()
	loggerEvent := zeroLogger.Log().
		Str("audience", "audit").
		Str("type", string(auditLogType)).
		AnErr("error", logError).
		Str("tenant", tenant.ID.String()).
		Str("http_request_id", context.Response().Header().Get(echo.HeaderXRequestID)).
		Str("source_ip", context.RealIP()).
		Str("user_agent", context.Request().UserAgent()).
		Str("time", now.Format(time.RFC3339Nano)).
		Str("time_unix", strconv.FormatInt(now.Unix(), 10))

	if user != nil {
		loggerEvent.Str("user_id", *user)
	}

	loggerEvent.Send()
}
