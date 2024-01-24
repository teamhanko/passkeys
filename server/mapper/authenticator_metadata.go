package mapper

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/gofrs/uuid"
	kjson "github.com/knadh/koanf/parsers/json"
	"github.com/teamhanko/passkey-server/utils"
	"log"
)

//go:embed aaguid.json
var authenticatorMetadataJson []byte

type Authenticator struct {
	Name      string `json:"name"`
	IconLight string `json:"icon_light"`
	IconDark  string `json:"icon_dark"`
}

type AuthenticatorMetadata map[string]Authenticator

func (w AuthenticatorMetadata) GetNameForAaguid(aaguid uuid.UUID) *string {
	if w != nil {
		if webauthnAaguid, ok := w[aaguid.String()]; ok {
			return &webauthnAaguid.Name
		}
	}

	return nil
}

func LoadAuthenticatorMetadata(authenticatorMetadataFile *string) AuthenticatorMetadata {
	k, err := utils.LoadFile(authenticatorMetadataFile, kjson.Parser())

	if err != nil {
		log.Println(err)
		return nil
	}

	var authenticatorMetadata AuthenticatorMetadata

	if k == nil {
		log.Println("no authenticator metadata file provided. Trying embedded file.")

		authenticatorMetadata, err := LoadEmbedded()
		if err != nil {
			log.Println("unable to use embedded authenticator metadata file. Skipping ")
			return nil
		}

		return authenticatorMetadata
	}

	err = k.Unmarshal("", &authenticatorMetadata)
	if err != nil {
		log.Println(fmt.Errorf("unable to unmarshal authenticator metadata file: %w", err))
		return nil
	}

	return authenticatorMetadata
}

func LoadEmbedded() (AuthenticatorMetadata, error) {
	var authMeta AuthenticatorMetadata
	err := json.Unmarshal(authenticatorMetadataJson, &authMeta)
	if err != nil {
		fmt.Println(fmt.Errorf("unable to unmarshal embedded authenticator metadata file: %w", err))
		return nil, err
	}

	return authMeta, nil
}
