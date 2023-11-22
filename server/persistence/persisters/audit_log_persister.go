package persisters

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type AuditLogPersister interface {
	Create(auditLog models.AuditLog) error
	List(options AuditLogOptions) ([]models.AuditLog, error)
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

type AuditLogOptions struct {
	Page     int
	PerPage  int
	Start    *time.Time
	End      *time.Time
	Types    []string
	UserId   string
	Ip       string
	Search   string
	TenantId string
}

func (p *auditLogPersister) List(options AuditLogOptions) ([]models.AuditLog, error) {
	var auditLogs []models.AuditLog

	query := p.database.Q()
	query = p.addOptionsToSqlQuery(query, options)
	err := query.Paginate(options.Page, options.PerPage).Order("created_at desc").All(&auditLogs)

	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return auditLogs, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch auditLogs: %w", err)
	}

	return auditLogs, nil
}

func (p *auditLogPersister) Count(options AuditLogOptions) (int, error) {
	query := p.database.Q()
	query = p.addOptionsToSqlQuery(query, options)
	count, err := query.Count(&models.AuditLog{})
	if err != nil {
		return 0, fmt.Errorf("failed to get auditLog count: %w", err)
	}

	return count, nil
}

func (p *auditLogPersister) addOptionsToSqlQuery(query *pop.Query, options AuditLogOptions) *pop.Query {
	if options.Start != nil {
		query = query.Where("created_at > ?", options.Start)
	}
	if options.End != nil {
		query = query.Where("created_at < ?", options.End)
	}

	if len(options.Types) > 0 {
		joined := "'" + strings.Join(options.Types, "','") + "'"
		query = query.Where(fmt.Sprintf("type IN (%s)", joined))
	}

	if len(options.UserId) > 0 {
		query = query.Where("actor_user_id LIKE ?", "%"+options.UserId+"%")
	}

	if len(options.Ip) > 0 {
		query = query.Where("meta_source_ip LIKE ?", "%"+options.Ip+"%")
	}

	if len(options.TenantId) > 0 {
		switch p.database.Dialect.Name() {
		case "postgres", "cockroach":
			query = query.Where("tenant_id::text = ?", options.TenantId)
		case "mysql", "mariadb":
			query = query.Where("tenant_id = ?", options.TenantId)
		}
	}

	if len(options.Search) > 0 {
		arg := "%" + options.Search + "%"
		query = query.Where("(meta_source_ip LIKE ? OR actor_user_id LIKE ?)", arg, arg)
	}

	return query
}
