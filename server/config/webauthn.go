package config

import (
	"errors"
	"fmt"
	"golang.org/x/exp/slices"
	"strings"
)

type Webauthn struct {
	RelyingParty     RelyingParty `yaml:"relying_party" json:"relying_party,omitempty" koanf:"relying_party" split_words:"true"`
	Timeout          int          `yaml:"timeout" json:"timeout,omitempty" koanf:"timeout" jsonschema:"default=60000"`
	UserVerification string       `yaml:"user_verification" json:"user_verification,omitempty" koanf:"user_verification" split_words:"true" jsonschema:"default=preferred,enum=required,enum=preferred,enum=discouraged"`
}

func (w *Webauthn) Validate() error {
	validUv := []string{
		"required",
		"preferred",
		"discouraged",
	}

	if !slices.Contains(validUv, w.UserVerification) {
		return fmt.Errorf("expected user_verification to be one of [%s], got: '%s'", strings.Join(validUv, ", "), w.UserVerification)
	}

	err := w.RelyingParty.Validate()
	if err != nil {
		return err
	}

	return nil
}

type RelyingParty struct {
	Id          string   `yaml:"id" json:"id,omitempty" koanf:"id" jsonschema:"default=localhost"`
	DisplayName string   `yaml:"display_name" json:"display_name,omitempty" koanf:"display_name" split_words:"true" jsonschema:"default=Hanko Passkey Service"`
	Icon        string   `yaml:"icon" json:"icon,omitempty" koanf:"icon"`
	Origins     []string `yaml:"origins" json:"origins,omitempty" koanf:"origins" jsonschema:"minItems=1"`
}

func (r *RelyingParty) Validate() error {
	if len(r.Origins) == 0 {
		return errors.New("at least one origin must be defined")
	}

	return nil
}
