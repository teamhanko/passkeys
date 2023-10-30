package jwk

import (
	"encoding/json"
	"github.com/gofrs/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/teamhanko/passkey-server/crypto/aes_gcm"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
	"time"
)

type Manager interface {
	// GenerateKey is used to generate a jwk Key
	GenerateKey(tenantId uuid.UUID) (*models.Jwk, error)
	// GetPublicKeys returns all Public keys that are persisted
	GetPublicKeys(tenantId uuid.UUID) (jwk.Set, error)
	// GetSigningKey returns the last added private key that is used for signing
	GetSigningKey(tenantId uuid.UUID) (jwk.Key, error)
}

type DefaultManager struct {
	encrypter *aes_gcm.AESGCM
	persister persisters.JwkPersister
}

// NewDefaultManager returns a DefaultManager that reads and persists the jwks to database and generates jwks if a new secret gets added to the config.
func NewDefaultManager(keys []string, tenantId uuid.UUID, persister persisters.JwkPersister) (Manager, error) {
	encrypter, err := aes_gcm.NewAESGCM(keys)
	if err != nil {
		return nil, err
	}
	manager := &DefaultManager{
		encrypter: encrypter,
		persister: persister,
	}

	foundKeys, err := persister.GetAllForTenant(tenantId)
	if err != nil {
		return nil, err
	}

	if len(keys) > len(foundKeys) {
		keysToCreate := len(keys) - len(foundKeys)

		for i := 0; i < keysToCreate; i++ {
			_, err := manager.GenerateKey(tenantId)
			if err != nil {
				return nil, err
			}
		}
	}

	return manager, nil
}

func (m *DefaultManager) GenerateKey(tenantId uuid.UUID) (*models.Jwk, error) {
	rsa := &RSAKeyGenerator{}
	id, _ := uuid.NewV4()
	key, err := rsa.Generate(id.String())
	if err != nil {
		return nil, err
	}
	marshalled, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	encryptedKey, err := m.encrypter.Encrypt(marshalled)
	if err != nil {
		return nil, err
	}

	model := models.Jwk{
		TenantID:  tenantId,
		KeyData:   encryptedKey,
		CreatedAt: time.Now(),
	}

	err = m.persister.Create(model)
	if err != nil {
		return nil, err
	}

	return &model, nil
}

func (m *DefaultManager) GetSigningKey(tenantId uuid.UUID) (jwk.Key, error) {
	sigModel, err := m.persister.GetLast(tenantId)
	if err != nil {
		return nil, err
	}
	k, err := m.encrypter.Decrypt(sigModel.KeyData)
	if err != nil {
		return nil, err
	}

	key, err := jwk.ParseKey(k)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (m *DefaultManager) GetPublicKeys(tenantId uuid.UUID) (jwk.Set, error) {
	modelList, err := m.persister.GetAllForTenant(tenantId)
	if err != nil {
		return nil, err
	}

	publicKeys := jwk.NewSet()
	for _, model := range modelList {
		k, err := m.encrypter.Decrypt(model.KeyData)
		if err != nil {
			return nil, err
		}

		key, err := jwk.ParseKey(k)

		if err != nil {
			return nil, err
		}

		publicKey, err := jwk.PublicKeyOf(key)
		if err != nil {
			return nil, err
		}
		err = publicKeys.AddKey(publicKey)
		if err != nil {
			return nil, err
		}
	}

	return publicKeys, nil
}
