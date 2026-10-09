package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/api/dto/admin/request"
	"github.com/teamhanko/passkey-server/api/dto/admin/response"
	"github.com/teamhanko/passkey-server/config"
	"net/http"
	"net/http/httptest"
)

func (s *adminSuite) TestAdminRouter_ApiKey_List() {
	s.SkipOnShort()

	tests := []struct {
		Name     string
		TenantID string

		SimulateBrokenDB bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
		ExpectedCount         int
	}{
		{
			Name:     "success",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			ExpectedCount:         1,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: "\"name\":\"API KEY 1\",\"secret\":",
		},
		{
			Name:     "unknown tenant",
			TenantID: "00000000-0000-0000-0000-000000000000",

			ExpectedCount:         0,
			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:     "no api key",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396d",

			ExpectedCount:         0,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: "[]",
		},
		{
			Name:     "malformed tenant",
			TenantID: "malformed",

			ExpectedCount:         0,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:     "broken db",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			SimulateBrokenDB: true,

			ExpectedCount:         0,
			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadFixtures("../../test/fixtures/common")
			s.Require().NoError(err)

			adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)

			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/tenants/%s/secrets/api", currentTest.TenantID), nil)
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDB {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			adminRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)

			if rec.Code == http.StatusOK {
				var requestBody response.SecretResponseListDto
				err = json.Unmarshal(rec.Body.Bytes(), &requestBody)
				s.Require().NoError(err)

				s.Assert().Len(requestBody, currentTest.ExpectedCount)
			}
		})
	}
}

func (s *adminSuite) TestAdminRouter_ApiKey_Create() {
	s.SkipOnShort()

	tests := []struct {
		Name        string
		TenantID    string
		RequestBody interface{}

		OmitRequestBody  bool
		SimulateBrokenDB bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:        "success",
			TenantID:    "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: request.CreateSecretDto{Name: "test-secret"},

			ExpectedStatusCode:    http.StatusCreated,
			ExpectedStatusMessage: "\"name\":\"test-secret\",\"secret\":",
		},
		{
			Name:        "api key already exists",
			TenantID:    "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: request.CreateSecretDto{Name: "API KEY 1"},

			ExpectedStatusCode:    http.StatusConflict,
			ExpectedStatusMessage: "Secret with this name already exists",
		},
		{
			Name:     "malformed request body",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: struct {
				Lorem string `json:"lorem"`
			}{
				Lorem: "Lorem ipsum",
			},

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "name is a required field",
		},
		{
			Name:     "missing request body",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			OmitRequestBody: true,

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "name is a required field",
		},
		{
			Name:        "unknown tenant",
			TenantID:    "00000000-0000-0000-0000-000000000000",
			RequestBody: request.CreateSecretDto{Name: "test-secret"},

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:        "malformed tenant",
			TenantID:    "malformed",
			RequestBody: request.CreateSecretDto{Name: "test-secret"},

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:        "broken db",
			TenantID:    "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: request.CreateSecretDto{Name: "test-secret"},

			SimulateBrokenDB: true,

			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadFixtures("../../test/fixtures/common")
			s.Require().NoError(err)

			adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)

			var req *http.Request
			if currentTest.OmitRequestBody {
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/tenants/%s/secrets/api", currentTest.TenantID), nil)
			} else {
				body, err := json.Marshal(currentTest.RequestBody)
				s.Require().NoError(err)

				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/tenants/%s/secrets/api", currentTest.TenantID), bytes.NewReader(body))
			}
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDB {
				err = s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			adminRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)
		})
	}
}

func (s *adminSuite) TestAdminRouter_ApiKey_Remove() {
	s.SkipOnShort()

	tests := []struct {
		Name     string
		TenantID string
		ApiKeyID string

		SimulateBrokenDB bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:     "success",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKeyID: "b8abe127-d122-459f-a0f9-86a569e684b5",

			ExpectedStatusCode: http.StatusNoContent,
		},
		{
			Name:     "unknown tenant",
			TenantID: "00000000-0000-0000-0000-000000000000",
			ApiKeyID: "b8abe127-d122-459f-a0f9-86a569e684b5",

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:     "malformed tenant",
			TenantID: "malformed",
			ApiKeyID: "b8abe127-d122-459f-a0f9-86a569e684b5",

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:     "unknown secret",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKeyID: "b8abe128-d122-459f-a0f9-86a569e684b5",

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "secret with ID 'b8abe128-d122-459f-a0f9-86a569e684b5' not found",
		},
		{
			Name:     "malformed secret",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKeyID: "malformed",

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "SecretId must be a valid",
		},
		{
			Name:     "broken db",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKeyID: "b8abe127-d122-459f-a0f9-86a569e684b5",

			SimulateBrokenDB: true,

			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadFixtures("../../test/fixtures/common")
			s.Require().NoError(err)

			oldTenant, err := s.Storage.GetTenantPersister(nil).Get(uuid.FromStringOrNil(currentTest.TenantID))
			s.Require().NoError(err)

			adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)

			req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/tenants/%s/secrets/api/%s", currentTest.TenantID, currentTest.ApiKeyID), nil)
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDB {
				err = s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			adminRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)

			if rec.Code == http.StatusNoContent {
				tenant, err := s.Storage.GetTenantPersister(nil).Get(uuid.FromStringOrNil(currentTest.TenantID))
				s.Require().NoError(err)

				s.Assert().NotEqual(len(oldTenant.Config.Secrets), len(tenant.Config.Secrets))
			}
		})
	}
}

func (s *adminSuite) TestAdminRouter_JWK_List() {
	s.SkipOnShort()

	tests := []struct {
		Name     string
		TenantID string

		SimulateBrokenDB bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
		ExpectedCount         int
	}{
		{
			Name:     "success",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			ExpectedCount:         1,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: "\"name\":\"JWK KEY 1\",\"secret\":",
		},
		{
			Name:     "unknown tenant",
			TenantID: "00000000-0000-0000-0000-000000000000",

			ExpectedCount:         0,
			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:     "no jwk key",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396d",

			ExpectedCount:         0,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: "[]",
		},
		{
			Name:     "malformed tenant",
			TenantID: "malformed",

			ExpectedCount:         0,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:     "broken db",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			SimulateBrokenDB: true,

			ExpectedCount:         0,
			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadFixtures("../../test/fixtures/common")
			s.Require().NoError(err)

			adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)

			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/tenants/%s/secrets/jwk", currentTest.TenantID), nil)
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDB {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			adminRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)

			if rec.Code == http.StatusOK {
				var requestBody response.SecretResponseListDto
				err = json.Unmarshal(rec.Body.Bytes(), &requestBody)
				s.Require().NoError(err)

				s.Assert().Len(requestBody, currentTest.ExpectedCount)
			}
		})
	}
}

func (s *adminSuite) TestAdminRouter_JWK_Create() {
	s.SkipOnShort()

	tests := []struct {
		Name        string
		TenantID    string
		RequestBody interface{}

		OmitRequestBody  bool
		SimulateBrokenDB bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:        "success",
			TenantID:    "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: request.CreateSecretDto{Name: "test-secret"},

			ExpectedStatusCode:    http.StatusCreated,
			ExpectedStatusMessage: "\"name\":\"test-secret\",\"secret\":",
		},
		{
			Name:        "jwk key already exists",
			TenantID:    "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: request.CreateSecretDto{Name: "JWK KEY 1"},

			ExpectedStatusCode:    http.StatusConflict,
			ExpectedStatusMessage: "Secret with this name already exists",
		},
		{
			Name:     "malformed request body",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: struct {
				Lorem string `json:"lorem"`
			}{
				Lorem: "Lorem ipsum",
			},

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "name is a required field",
		},
		{
			Name:     "missing request body",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			OmitRequestBody: true,

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "name is a required field",
		},
		{
			Name:        "unknown tenant",
			TenantID:    "00000000-0000-0000-0000-000000000000",
			RequestBody: request.CreateSecretDto{Name: "test-secret"},

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:        "malformed tenant",
			TenantID:    "malformed",
			RequestBody: request.CreateSecretDto{Name: "test-secret"},

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:        "broken db",
			TenantID:    "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: request.CreateSecretDto{Name: "test-secret"},

			SimulateBrokenDB: true,

			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadFixtures("../../test/fixtures/common")
			s.Require().NoError(err)

			adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)

			var req *http.Request
			if currentTest.OmitRequestBody {
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/tenants/%s/secrets/jwk", currentTest.TenantID), nil)
			} else {
				body, err := json.Marshal(currentTest.RequestBody)
				s.Require().NoError(err)

				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/tenants/%s/secrets/jwk", currentTest.TenantID), bytes.NewReader(body))
			}
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDB {
				err = s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			adminRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)
		})
	}
}

func (s *adminSuite) TestAdminRouter_JWK_Remove() {
	s.SkipOnShort()

	tests := []struct {
		Name     string
		TenantID string
		JwkKeyID string

		SimulateBrokenDB bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:     "success",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			JwkKeyID: "b8abe127-d122-459f-a0f9-86a569e684b6",

			ExpectedStatusCode: http.StatusNoContent,
		},
		{
			Name:     "unknown tenant",
			TenantID: "00000000-0000-0000-0000-000000000000",
			JwkKeyID: "b8abe127-d122-459f-a0f9-86a569e684b6",

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:     "malformed tenant",
			TenantID: "malformed",
			JwkKeyID: "b8abe127-d122-459f-a0f9-86a569e684b6",

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:     "unknown secret",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			JwkKeyID: "b8abe128-d122-459f-a0f9-86a569e684b5",

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "secret with ID 'b8abe128-d122-459f-a0f9-86a569e684b5' not found",
		},
		{
			Name:     "malformed secret",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			JwkKeyID: "malformed",

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "SecretId must be a valid",
		},
		{
			Name:     "broken db",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			JwkKeyID: "b8abe127-d122-459f-a0f9-86a569e684b6",

			SimulateBrokenDB: true,

			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadFixtures("../../test/fixtures/common")
			s.Require().NoError(err)

			oldTenant, err := s.Storage.GetTenantPersister(nil).Get(uuid.FromStringOrNil(currentTest.TenantID))
			s.Require().NoError(err)

			adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)

			req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/tenants/%s/secrets/jwk/%s", currentTest.TenantID, currentTest.JwkKeyID), nil)
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDB {
				err = s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			adminRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)

			if rec.Code == http.StatusNoContent {
				tenant, err := s.Storage.GetTenantPersister(nil).Get(uuid.FromStringOrNil(currentTest.TenantID))
				s.Require().NoError(err)

				s.Assert().NotEqual(len(oldTenant.Config.Secrets), len(tenant.Config.Secrets))
			}
		})
	}
}
