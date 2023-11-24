package jwt

import (
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	hankoJwk "github.com/teamhanko/passkey-server/crypto/jwk"
	"github.com/teamhanko/passkey-server/persistence/models"
	"time"
)

type Generator interface {
	Sign(jwt.Token) ([]byte, error)
	Verify([]byte) (jwt.Token, error)
	Generate(userId string, credentialId string) (string, error)
	GenerateForTransaction(userId string, credentialId string, transactionIdentifier string) (string, error)
}

const (
	JwtExpirationDuration = 300 // 5 Min from Creation to Expire
)

// Generator is used to sign and verify JWTs
type generator struct {
	signatureKey jwk.Key
	verKeys      jwk.Set
	config       *models.WebauthnConfig
}

// NewGenerator returns a new jwt generator which signs JWTs with the given signing key and verifies JWTs with the given verificationKeys
func NewGenerator(cfg *models.WebauthnConfig, jwkManager hankoJwk.Manager, tenantId uuid.UUID) (Generator, error) {
	signatureKey, err := jwkManager.GetSigningKey(tenantId)
	const jwkGenFailure = "failed to create jwk jwtGenerator: %w"
	if err != nil {
		return nil, fmt.Errorf(jwkGenFailure, err)
	}

	verificationKeys, err := jwkManager.GetPublicKeys(tenantId)
	if err != nil {
		return nil, fmt.Errorf(jwkGenFailure, err)
	}

	pubKeySet, err := jwk.PublicSetOf(verificationKeys)
	if err != nil {
		return nil, err
	}
	return &generator{
		signatureKey: signatureKey,
		verKeys:      pubKeySet,
		config:       cfg,
	}, nil
}

// Sign a JWT with the signing key and returns it
func (g *generator) Sign(token jwt.Token) ([]byte, error) {
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, g.signatureKey))
	if err != nil {
		return nil, fmt.Errorf("failed to sign jwt: %w", err)
	}
	return signed, nil
}

// Verify verifies a JWT, using the verificationKeys and returns the parsed JWT
func (g *generator) Verify(signed []byte) (jwt.Token, error) {
	token, err := jwt.Parse(signed, jwt.WithKeySet(g.verKeys))
	if err != nil {
		return nil, fmt.Errorf("failed to verify jwt: %w", err)
	}
	return token, nil
}

func (g *generator) generateDefaultToken(userId string, credentialId string) jwt.Token {
	issuedAt := time.Now()
	expiresAt := issuedAt.Add(time.Second * JwtExpirationDuration)

	token := jwt.New()
	_ = token.Set(jwt.SubjectKey, userId)
	_ = token.Set(jwt.IssuedAtKey, issuedAt)
	_ = token.Set(jwt.ExpirationKey, expiresAt)
	_ = token.Set(jwt.AudienceKey, []string{g.config.RelyingParty.RPId})
	_ = token.Set("cred", credentialId)

	return token
}

func (g *generator) signToken(token jwt.Token) (string, error) {
	signed, err := g.Sign(token)
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

func (g *generator) Generate(userId string, credentialId string) (string, error) {
	token := g.generateDefaultToken(userId, credentialId)
	return g.signToken(token)
}

func (g *generator) GenerateForTransaction(userId string, credentialId string, transactionIdentifier string) (string, error) {
	token := g.generateDefaultToken(userId, credentialId)
	_ = token.Set("trans", transactionIdentifier)

	return g.signToken(token)
}
