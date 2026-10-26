package router

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Exercise the claim through real normal, discoverable, and MFA login fixtures.
func (s *mainRouterSuite) assertLoginChallenge(handler http.Handler, tenantID, assertion string, body []byte) {
	parsed, err := protocol.ParseCredentialRequestResponse(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(assertion)))
	s.Require().NoError(err)
	var result struct {
		Token string `json:"token"`
	}
	s.Require().NoError(json.Unmarshal(body, &result))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/%s/.well-known/jwks.json", tenantID), nil))
	s.Require().Equal(http.StatusOK, rec.Code)
	keys, err := jwk.Parse(rec.Body.Bytes())
	s.Require().NoError(err)
	token, err := jwt.Parse([]byte(result.Token), jwt.WithKeySet(keys), jwt.WithValidate(true))
	s.Require().NoError(err)
	challenge, ok := token.Get("challenge")
	s.Require().True(ok)
	s.Equal(parsed.Response.CollectedClientData.Challenge, challenge)
}
