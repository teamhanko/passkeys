package utils

import (
	"fmt"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/providers/file"
)

func LoadFile(filePath *string, parser koanf.Parser) (*koanf.Koanf, error) {
	k := koanf.New(".")

	if filePath == nil || *filePath == "" {
		return nil, nil
	}

	if err := k.Load(file.Provider(*filePath), parser); err != nil {
		return nil, fmt.Errorf("failed to load file from '%s': %w", *filePath, err)
	}

	return k, nil
}
