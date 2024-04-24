package intern

import (
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type WebauthnUser struct {
	UserId              string
	Name                string
	Icon                string
	DisplayName         string
	WebauthnCredentials []models.WebauthnCredential
	IsMfaUser           bool
}

func NewWebauthnUser(user models.WebauthnUser, isMfaUser bool) *WebauthnUser {
	return &WebauthnUser{
		UserId:              user.UserID,
		Name:                user.Name,
		Icon:                user.Icon,
		DisplayName:         user.DisplayName,
		WebauthnCredentials: user.WebauthnCredentials,
		IsMfaUser:           isMfaUser,
	}
}

func (u *WebauthnUser) WebAuthnID() []byte {
	return []byte(u.UserId)
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
		if !u.IsMfaUser && credential.IsMFA {
			// Skip if request is not for an MFA cred but the credential is a mfa cred
			continue
		}

		cred := credential
		c := WebauthnCredentialFromModel(&cred)
		credentials = append(credentials, *c)
	}

	return credentials
}

func (u *WebauthnUser) FindCredentialById(credentialId string) *models.WebauthnCredential {
	for i := range u.WebauthnCredentials {
		if !u.IsMfaUser && u.WebauthnCredentials[i].IsMFA {
			// Skip if request is not for an MFA cred but the credential is a mfa cred
			continue
		}

		if u.WebauthnCredentials[i].ID == credentialId {
			return &u.WebauthnCredentials[i]
		}
	}

	return nil
}
