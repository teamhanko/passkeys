package config

import (
	"errors"
	"strings"
)

type Database struct {
	Database string `yaml:"database" json:"database,omitempty" koanf:"database" jsonschema:"default=hanko" jsonschema:"oneof_required=config"`
	User     string `yaml:"user" json:"user,omitempty" koanf:"user" jsonschema:"oneof_required=config"`
	Password string `yaml:"password" json:"password,omitempty" koanf:"password" jsonschema:"oneof_required=config"`
	Host     string `yaml:"host" json:"host,omitempty" koanf:"host" jsonschema:"oneof_required=config"`
	Port     string `yaml:"port" json:"port,omitempty" koanf:"port" jsonschema:"oneof_required=config,oneof_type=string;integer"`
	Dialect  string `yaml:"dialect" json:"dialect,omitempty" koanf:"dialect" jsonschema:"oneof_required=config,enum=postgres,enum=mysql,enum=cockroach"`
	Url      string `yaml:"url" json:"url,omitempty" koanf:"url" jsonschema:"oneof_required=url"`
}

func (d *Database) Validate() error {
	if len(strings.TrimSpace(d.Url)) > 0 {
		return nil
	}
	if len(strings.TrimSpace(d.Database)) == 0 {
		return errors.New("database must not be empty")
	}
	if len(strings.TrimSpace(d.User)) == 0 {
		return errors.New("user must not be empty")
	}
	if len(strings.TrimSpace(d.Host)) == 0 {
		return errors.New("host must not be empty")
	}
	if len(strings.TrimSpace(d.Port)) == 0 {
		return errors.New("port must not be empty")
	}
	if len(strings.TrimSpace(d.Dialect)) == 0 {
		return errors.New("dialect must not be empty")
	}

	return nil
}
