package config

import "errors"

type Secrets struct {
	ApiKeys []string `yaml:"api_keys" json:"api_keys" koanf:"api_keys"`
	Keys    []string `yaml:"keys" json:"keys" koanf:"keys" jsonschema:"minItems=1"`
}

func (secrets *Secrets) Validate() error {
	if len(secrets.ApiKeys) == 0 {
		return errors.New("at least one api key must be defined")
	}

	for _, apiKey := range secrets.ApiKeys {
		if len(apiKey) < 32 {
			return errors.New("all api keys must be at least 32 characters long")
		}
	}

	if len(secrets.Keys) == 0 {
		return errors.New("at least one secret key must be defined")
	}

	return nil
}
