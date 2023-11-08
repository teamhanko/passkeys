package persisters

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type AuditLogPersister interface {
	Create(auditLog models.AuditLog) error
	Get(id uuid.UUID) (*models.AuditLog, error)
	List(options AuditLogOptions) ([]models.AuditLog, error)
	Delete(auditLog models.AuditLog) error
	Count(options AuditLogOptions) (int, error)
}

type auditLogPersister struct {
	database *pop.Connection
}

func NewAuditLogPersister(database *pop.Connection) AuditLogPersister {
	return &auditLogPersister{
		database: database,
	}
}

func (p *auditLogPersister) Create(auditLog models.AuditLog) error {
	vErr, err := p.database.ValidateAndCreate(&auditLog)
	if err != nil {
		return fmt.Errorf("failed to store auditlog: %w", err)
	}
	if vErr != nil && vErr.HasAny() {
		return fmt.Errorf("auditlog object validation failed: %w", vErr)
	}

	return nil
}

func (p *auditLogPersister) Get(id uuid.UUID) (*models.AuditLog, error) {
	auditLog := models.AuditLog{}
	err := p.database.Eager().Find(&auditLog, id)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get auditlog: %w", err)
	}

	return &auditLog, nil
}

type AuditLogOptions struct {
	page    int
	perPage int
	start   *time.Time
	end     *time.Time
	types   []string
	userId  string
	ip      string
	search  string
}

func (p *auditLogPersister) List(options AuditLogOptions) ([]models.AuditLog, error) {
	var auditLogs []models.AuditLog

	query := p.database.Q()
	query = p.addQueryParamsToSqlQuery(query, options)
	err := query.Paginate(options.page, options.perPage).Order("created_at desc").All(&auditLogs)

	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return auditLogs, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch auditLogs: %w", err)
	}

	return auditLogs, nil
}

func (p *auditLogPersister) Delete(auditLog models.AuditLog) error {
	err := p.database.Eager().Destroy(&auditLog)
	if err != nil {
		return fmt.Errorf("failed to delete auditlog: %w", err)
	}

	return nil
}

func (p *auditLogPersister) Count(options AuditLogOptions) (int, error) {
	query := p.database.Q()
	query = p.addQueryParamsToSqlQuery(query, options)
	count, err := query.Count(&models.AuditLog{})
	if err != nil {
		return 0, fmt.Errorf("failed to get auditLog count: %w", err)
	}

	return count, nil
}

func (p *auditLogPersister) addQueryParamsToSqlQuery(query *pop.Query, options AuditLogOptions) *pop.Query {
	if options.start != nil {
		query = query.Where("created_at > ?", options.start)
	}
	if options.end != nil {
		query = query.Where("created_at < ?", options.end)
	}

	if len(options.types) > 0 {
		joined := "'" + strings.Join(options.types, "','") + "'"
		query = query.Where(fmt.Sprintf("type IN (%s)", joined))
	}

	if len(options.userId) > 0 {
		switch p.database.Dialect.Name() {
		case "postgres", "cockroach":
			query = query.Where("actor_user_id::text LIKE ?", "%"+options.userId+"%")
		case "mysql", "mariadb":
			query = query.Where("actor_user_id LIKE ?", "%"+options.userId+"%")
		}
	}

	if len(options.ip) > 0 {
		query = query.Where("meta_source_ip LIKE ?", "%"+options.ip+"%")
	}

	if len(options.search) > 0 {
		arg := "%" + options.search + "%"
		switch p.database.Dialect.Name() {
		case "postgres", "cockroach":
			query = query.Where("(actor_email LIKE ? OR meta_source_ip LIKE ? OR actor_user_id::text LIKE ?)", arg, arg, arg)
		case "mysql", "mariadb":
			query = query.Where("(actor_email LIKE ? OR meta_source_ip LIKE ? OR actor_user_id LIKE ?)", arg, arg, arg)
		}
	}

	return query
}
