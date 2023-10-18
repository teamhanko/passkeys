package config

import (
	"fmt"
	"github.com/kelseyhightower/envconfig"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"log"
	"strings"
)

var (
	DefaultConfigFilePath = "./config/config.yaml"
)

type Config struct {
	Server   Server   `yaml:"server" json:"server,omitempty" koanf:"server"`
	Database Database `yaml:"database" json:"database,omitempty" koanf:"database"`
	Secrets  Secrets  `yaml:"secrets" json:"secrets,omitempty" koanf:"secrets"`
	Webauthn Webauthn `yaml:"webauthn" json:"webauthn,omitempty" koanf:"webauthn"`
	AuditLog AuditLog `yaml:"audit_log" json:"audit_log,omitempty" koanf:"audit_log"`
	Log      Logger   `yaml:"log" json:"log,omitempty" koanf:"log"`
}

func (c *Config) Validate() error {
	err := c.Server.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate server config: %w", err)
	}

	err = c.Database.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate database config: %w", err)
	}

	err = c.Secrets.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate secrets: %w", err)
	}

	err = c.Webauthn.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate webauthn config: %w", err)
	}

	return nil
}

func Load(configFile *string) (*Config, error) {
	k := koanf.New(".")

	var err error

	if configFile == nil || strings.TrimSpace(*configFile) == "" {
		*configFile = DefaultConfigFilePath
	}

	if err = k.Load(file.Provider(*configFile), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("failed to load config from: %s: %w", *configFile, err)
	} else {
		log.Println("Using config file:", *configFile)
	}

	c := NewConfig()
	err = k.Unmarshal("", c)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := envconfig.Process("", c); err != nil {
		return nil, fmt.Errorf("failed to load config from env vars: %w", err)
	}

	if err = c.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate config: %s", err)
	}

	return c, nil
}

func NewConfig() *Config {
	return &Config{
		AuditLog: AuditLog{
			ConsoleOutput: AuditLogConsole{
				Enabled:      true,
				OutputStream: OutputStreamStdOut,
			},
		},
		Server: Server{
			Address: ":8000",
		},
		Database: Database{
			Database: "hanko-passkey",
		},
		Secrets: Secrets{},
		Webauthn: Webauthn{
			RelyingParty: RelyingParty{
				Id:          "localhost",
				DisplayName: "Hanko Passkey Service",
				Origins:     []string{"http://localhost:8000"},
			},
			UserVerification: "preferred",
			Timeout:          60000,
		},
	}
}
