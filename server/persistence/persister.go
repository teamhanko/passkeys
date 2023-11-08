package persistence

import (
	"embed"
	"fmt"

	"github.com/gobuffalo/pop/v6"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/persistence/persisters"
)

//go:embed migrations/*
var migrations embed.FS

type persister struct {
	Database *pop.Connection
}

type Persister interface {
	GetConnection() *pop.Connection
	Transaction(func(tx *pop.Connection) error) error
	GetAuditLogPersister(tx *pop.Connection) persisters.AuditLogPersister
	GetWebauthnCredentialPersister(tx *pop.Connection) persisters.WebauthnCredentialPersister
	GetWebauthnSessionDataPersister(tx *pop.Connection) persisters.WebauthnSessionDataPersister
	GetWebauthnUserPersister(tx *pop.Connection) persisters.WebauthnUserPersister
	GetJwkPersister(tx *pop.Connection) persisters.JwkPersister
	GetTenantPersister(tx *pop.Connection) persisters.TenantPersister
	GetSecretsPersister(tx *pop.Connection) persisters.SecretsPersister
	GetConfigPersister(tx *pop.Connection) persisters.ConfigPersister
	GetWebauthnConfigPersister(tx *pop.Connection) persisters.WebauthnConfigPersister
	GetWebauthnRelyingPartyPersister(tx *pop.Connection) persisters.WebauthnRelyingPartyPersister
	GetCorsPersister(tx *pop.Connection) persisters.CorsPersister
	GetAuditLogConfigPersister(tx *pop.Connection) persisters.AuditLogConfigPersister
}

type Migrator interface {
	MigrateUp() error
	MigrateDown(steps int) error
}

type Database interface {
	Migrator
	Persister
}

func NewDatabase(dbConfig config.Database) (Database, error) {
	connectionDetails := &pop.ConnectionDetails{
		Pool:     5,
		IdlePool: 0,
	}

	if len(dbConfig.Url) > 0 {
		connectionDetails.URL = dbConfig.Url
	} else {
		connectionDetails.Dialect = dbConfig.Dialect
		connectionDetails.Database = dbConfig.Database
		connectionDetails.Host = dbConfig.Host
		connectionDetails.Port = dbConfig.Port
		connectionDetails.User = dbConfig.User
		connectionDetails.Password = dbConfig.Password
	}

	database, err := pop.NewConnection(connectionDetails)
	if err != nil {
		return nil, err
	}

	if err := database.Open(); err != nil {
		return nil, err
	}

	return &persister{
		Database: database,
	}, nil
}

func (p *persister) MigrateUp() error {
	migrationBox, err := pop.NewMigrationBox(migrations, p.Database)
	if err != nil {
		return err
	}

	err = migrationBox.Up()
	if err != nil {
		return err
	}

	return nil
}

func (p *persister) MigrateDown(steps int) error {
	migrationBox, err := pop.NewMigrationBox(migrations, p.Database)
	if err != nil {
		return err
	}
	err = migrationBox.Down(steps)
	if err != nil {
		return err
	}
	return nil
}

func (p *persister) GetConnection() *pop.Connection {
	return p.Database
}

func (p *persister) Transaction(fn func(tx *pop.Connection) error) error {
	return p.Database.Transaction(fn)
}

func (p *persister) GetAuditLogPersister(tx *pop.Connection) persisters.AuditLogPersister {
	if tx == nil {
		return persisters.NewAuditLogPersister(p.Database)
	}

	return persisters.NewAuditLogPersister(tx)
}

func (p *persister) GetWebauthnCredentialPersister(tx *pop.Connection) persisters.WebauthnCredentialPersister {
	fmt.Println("Get Database Connection")
	if tx == nil {
		return persisters.NewWebauthnCredentialPersister(p.Database)
	}

	return persisters.NewWebauthnCredentialPersister(tx)
}

func (p *persister) GetWebauthnSessionDataPersister(tx *pop.Connection) persisters.WebauthnSessionDataPersister {
	if tx == nil {
		return persisters.NewWebauthnSessionDataPersister(p.Database)
	}

	return persisters.NewWebauthnSessionDataPersister(tx)
}

func (p *persister) GetWebauthnUserPersister(tx *pop.Connection) persisters.WebauthnUserPersister {
	if tx == nil {
		return persisters.NewWebauthnUserPersister(p.Database)
	}

	return persisters.NewWebauthnUserPersister(tx)
}

func (p *persister) GetJwkPersister(tx *pop.Connection) persisters.JwkPersister {
	if tx == nil {
		return persisters.NewJwkPersister(p.Database)
	}

	return persisters.NewJwkPersister(tx)
}

func (p *persister) GetTenantPersister(tx *pop.Connection) persisters.TenantPersister {
	if tx == nil {
		return persisters.NewTenantPersister(p.Database)
	}

	return persisters.NewTenantPersister(tx)
}

func (p *persister) GetSecretsPersister(tx *pop.Connection) persisters.SecretsPersister {
	if tx == nil {
		return persisters.NewSecretsPersister(p.Database)
	}

	return persisters.NewSecretsPersister(tx)
}

func (p *persister) GetConfigPersister(tx *pop.Connection) persisters.ConfigPersister {
	if tx == nil {
		return persisters.NewConfigPersister(p.Database)
	}

	return persisters.NewConfigPersister(tx)
}

func (p *persister) GetWebauthnConfigPersister(tx *pop.Connection) persisters.WebauthnConfigPersister {
	if tx == nil {
		return persisters.NewWebauthnConfigPersister(p.Database)
	}

	return persisters.NewWebauthnConfigPersister(tx)
}

func (p *persister) GetWebauthnRelyingPartyPersister(tx *pop.Connection) persisters.WebauthnRelyingPartyPersister {
	if tx == nil {
		return persisters.NewWebauthnRelyingPartyPersister(p.Database)
	}

	return persisters.NewWebauthnRelyingPartyPersister(tx)
}

func (p *persister) GetCorsPersister(tx *pop.Connection) persisters.CorsPersister {
	if tx == nil {
		return persisters.NewCorsPersister(p.Database)
	}

	return persisters.NewCorsPersister(tx)
}

func (p *persister) GetAuditLogConfigPersister(tx *pop.Connection) persisters.AuditLogConfigPersister {
	if tx == nil {
		return persisters.NewAuditLogConfigPersister(p.Database)
	}

	return persisters.NewAuditLogConfigPersister(tx)
}
