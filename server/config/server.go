package config

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

type Server struct {
	Address string `yaml:"address" json:"address,omitempty" koanf:"address"`
	Cors    Cors   `yaml:"cors" json:"cors,omitempty" koanf:"cors"`
}

func (s *Server) Validate() error {
	if len(strings.TrimSpace(s.Address)) == 0 {
		return errors.New("field Address must not be empty")
	}

	if _, _, err := net.SplitHostPort(s.Address); err != nil {
		return errors.New("field Address must be formatted as 'host%zone:port', '[host]:port' or '[host%zone]:port'")
	}

	if err := s.Cors.Validate(); err != nil {
		return err
	}
	return nil
}

type Cors struct {
	AllowOrigins                []string `yaml:"allow_origins" json:"allow_origins" koanf:"allow_origins" split_words:"true"`
	UnsafeWildcardOriginAllowed bool     `yaml:"unsafe_wildcard_origin_allowed" json:"unsafe_wildcard_origin_allowed,omitempty" koanf:"unsafe_wildcard_origin_allowed" split_words:"true" jsonschema:"default=false"`
}

func (cors *Cors) Validate() error {
	for _, origin := range cors.AllowOrigins {
		if origin == "*" && !cors.UnsafeWildcardOriginAllowed {
			return fmt.Errorf("found wildcard '*' origin in server.cors.allow_origins, if this is intentional set server.cors.unsafe_wildcard_origin_allowed to true")
		}
	}

	return nil
}
