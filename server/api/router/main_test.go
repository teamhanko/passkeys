package router

import (
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/suite"
	"github.com/teamhanko/passkey-server/config"
	hankoJwk "github.com/teamhanko/passkey-server/crypto/jwk"
	"github.com/teamhanko/passkey-server/test"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMainRouterSuite(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(mainRouterSuite))
}

type mainRouterSuite struct {
	test.Suite
}

func (s *mainRouterSuite) TestMainRouter_New() {
	mainRouter := NewMainRouter(&config.Config{}, s.Storage, nil)
	s.Assert().NotEmpty(mainRouter)
}

func (s *mainRouterSuite) TestMainRouter_Status_Success() {
	s.SkipOnShort()

	mainRouter := NewMainRouter(&config.Config{}, s.Storage, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mainRouter.ServeHTTP(rec, req)

	s.Assert().Equal(http.StatusOK, rec.Code)
}

func (s *mainRouterSuite) TestMainRouter_Status_Broken_DB() {
	s.SkipOnShort()

	err := s.Storage.MigrateDown(-1)
	s.Require().NoError(err)

	mainRouter := NewMainRouter(&config.Config{}, s.Storage, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mainRouter.ServeHTTP(rec, req)

	s.Assert().Equal(http.StatusInternalServerError, rec.Code)
}

func (s *mainRouterSuite) TestMainRouter_WellKnown() {
	s.SkipOnShort()

	tests := []struct {
		Name     string
		TenantId string

		SimulateBrokenDb bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:               "success",
			TenantId:           "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ExpectedStatusCode: http.StatusOK,
		},
		{
			Name:                  "missing tenant",
			TenantId:              "00000000-0000-0000-0000-000000000000",
			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:                  "malformed tenant",
			TenantId:              "malformed",
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:                  "missing jwk",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396d",
			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
		},
		{
			Name:                  "broken jwk",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396c",
			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
		},
		{
			Name:                  "broken db",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
			SimulateBrokenDb:      true,
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadMultipleFixtures([]string{"../../test/fixtures/common"})
			s.Require().NoError(err)

			mainRouter := NewMainRouter(&config.Config{}, s.Storage, nil)

			if currentTest.SimulateBrokenDb {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/%s/.well-known/jwks.json", currentTest.TenantId), nil)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mainRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			if rec.Code == http.StatusOK {
				jwkManager := mainRouter.AcquireContext().Get("jwk_manager").(hankoJwk.Manager)
				s.Require().NotNil(jwkManager)

				keys, err := jwkManager.GetPublicKeys(uuid.FromStringOrNil(currentTest.TenantId))
				s.Require().NoError(err)
				s.Require().Greater(keys.Len(), 0)

				key, ok := keys.Key(0)
				s.Require().True(ok)
				s.Require().NotNil(key)

				s.Assert().Contains(rec.Body.String(), key.KeyID())
			} else {
				s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)
			}
		})
	}
}
