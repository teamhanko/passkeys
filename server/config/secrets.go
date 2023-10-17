package config

import "errors"

type Secrets struct {
	ApiKey string   `yaml:"api_key" json:"api_key" koanf:"api_key"`
	Keys   []string `yaml:"keys" json:"keys" koanf:"keys" jsonschema:"minItems=1"`
}

func (secrets *Secrets) Validate() error {
	if len(secrets.Keys) == 0 {
		return errors.New("at least one secret key must be defined")
	}

	return nil
}
