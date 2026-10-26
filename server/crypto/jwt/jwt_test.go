package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
	"github.com/teamhanko/passkey-server/persistence/models"
)

func TestAuthenticationTokenClaims(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key, err := jwk.FromRaw(privateKey)
	require.NoError(t, err)
	g := &generator{signatureKey: key, config: &models.WebauthnConfig{
		RelyingParty: models.RelyingParty{RPId: "example.com"},
	}}
	challenge := "a-_Base64urlChallenge"

	for _, test := range []struct {
		name            string
		generate        func() (string, error)
		wantChallenge   bool
		wantTransaction bool
	}{
		{"login", func() (string, error) { return g.GenerateForLogin("user", "credential", challenge) }, true, false},
		{"registration", func() (string, error) { return g.Generate("user", "credential") }, false, false},
		{"transaction", func() (string, error) { return g.GenerateForTransaction("user", "credential", "payment") }, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			signed, err := test.generate()
			require.NoError(t, err)
			token, err := jwxjwt.Parse([]byte(signed), jwxjwt.WithKey(jwa.RS256, &privateKey.PublicKey), jwxjwt.WithValidate(true))
			require.NoError(t, err)
			require.Equal(t, "user", token.Subject())
			require.Equal(t, []string{"example.com"}, token.Audience())
			require.Equal(t, JwtExpirationDuration, int(token.Expiration().Sub(token.IssuedAt()).Seconds()))
			cred, ok := token.Get("cred")
			require.True(t, ok)
			require.Equal(t, "credential", cred)
			actual, ok := token.Get("challenge")
			require.Equal(t, test.wantChallenge, ok)
			if test.wantChallenge {
				require.Equal(t, challenge, actual)
			}
			transaction, ok := token.Get("trans")
			require.Equal(t, test.wantTransaction, ok)
			if test.wantTransaction {
				require.Equal(t, "payment", transaction)
			}
		})
	}

	signed, err := g.GenerateForLogin("user", "credential", "")
	require.Error(t, err)
	require.Empty(t, signed)
}
