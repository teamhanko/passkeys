package config

import (
	"errors"
	"fmt"
	"github.com/kelseyhightower/envconfig"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"log"
	"net"
	"strings"
)

var (
	DefaultConfigFilePath = "./config/config.yaml"
)

type Config struct {
	Address      string   `yaml:"address" json:"address,omitempty" koanf:"address"`
	AdminAddress string   `yaml:"admin_address" json:"admin_address,omitempty" koanf:"admin_address"`
	Database     Database `yaml:"database" json:"database,omitempty" koanf:"database"`
	Log          Logger   `yaml:"log" json:"log,omitempty" koanf:"log"`
}

func (c *Config) Validate() error {
	if len(strings.TrimSpace(c.Address)) == 0 {
		return errors.New("field Address must not be empty")
	}

	if _, _, err := net.SplitHostPort(c.Address); err != nil {
		return errors.New("field Address must be formatted as 'host%zone:port', '[host]:port' or '[host%zone]:port'")
	}

	if len(strings.TrimSpace(c.AdminAddress)) == 0 {
		return errors.New("field AdminAddress must not be empty")
	}

	if _, _, err := net.SplitHostPort(c.AdminAddress); err != nil {
		return errors.New("field AdminAddress must be formatted as 'host%zone:port', '[host]:port' or '[host%zone]:port'")
	}

	err := c.Database.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate database config: %w", err)
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
		Address:      ":8000",
		AdminAddress: ":8001",
		Database: Database{
			Database: "passkey",
		},
	}
}

const (
	OutputStreamStdOut = "stdout"
	OutputStreamStdErr = "stderr"
)
