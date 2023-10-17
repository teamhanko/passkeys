package intern

import (
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type WebauthnUser struct {
	UserId              uuid.UUID
	Name                string
	Icon                string
	DisplayName         string
	WebauthnCredentials []models.WebauthnCredential
}

func NewWebauthnUser(user models.WebauthnUser) *WebauthnUser {
	return &WebauthnUser{
		UserId:              user.UserID,
		Name:                user.Name,
		Icon:                user.Icon,
		DisplayName:         user.DisplayName,
		WebauthnCredentials: user.Credentials,
	}
}

func (u *WebauthnUser) WebAuthnID() []byte {
	return u.UserId.Bytes()
}

func (u *WebauthnUser) WebAuthnName() string {
	return u.Name
}

func (u *WebauthnUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *WebauthnUser) WebAuthnIcon() string {
	return u.Icon
}

func (u *WebauthnUser) WebAuthnCredentials() []webauthn.Credential {
	var credentials []webauthn.Credential
	for _, credential := range u.WebauthnCredentials {
		cred := credential
		c := WebauthnCredentialFromModel(&cred)
		credentials = append(credentials, *c)
	}

	return credentials
}

func (u *WebauthnUser) FindCredentialById(credentialId string) *models.WebauthnCredential {
	for i := range u.WebauthnCredentials {
		if u.WebauthnCredentials[i].ID == credentialId {
			return &u.WebauthnCredentials[i]
		}
	}

	return nil
}
