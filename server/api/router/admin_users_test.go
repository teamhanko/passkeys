package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/api/dto/admin/request"
	"github.com/teamhanko/passkey-server/api/dto/admin/response"
	publicResponse "github.com/teamhanko/passkey-server/api/dto/response"
	"github.com/teamhanko/passkey-server/config"
	"net/http"
	"net/http/httptest"
)

func (s *adminSuite) TestAdminRouter_Users_List() {
	s.SkipOnShort()

	tests := []struct {
		Name        string
		TenantID    string
		RequestBody interface{}

		OmitRequestBody  bool
		SimulateBrokenDB bool

		ExpectedCount         int
		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:     "success",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			RequestBody: request.UserListRequest{
				PerPage:       3,
				Page:          1,
				SortDirection: "asc",
			},

			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: "[",
			ExpectedCount:         3,
		},
		{
			Name:     "success with reduced per page",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			RequestBody: request.UserListRequest{
				PerPage:       1,
				Page:          1,
				SortDirection: "asc",
			},

			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: "[",
			ExpectedCount:         1,
		},
		{
			Name:     "success with minimal request",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			RequestBody: request.UserListRequest{},

			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: "[",
			ExpectedCount:         3,
		},
		{
			Name:     "success without request body",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			OmitRequestBody: true,

			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: "[",
			ExpectedCount:         3,
		},
		{
			Name:     "success with malformed request body",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: struct {
				Lorem string `json:"lorem"`
			}{
				Lorem: "lorem ipsum",
			},

			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: "[",
			ExpectedCount:         3,
		},
		{
			Name:     "unknown tenant",
			TenantID: "00000000-0000-0000-0000-000000000000",

			OmitRequestBody: true,

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
			ExpectedCount:         0,
		},
		{
			Name:     "malformed tenant",
			TenantID: "malformed",

			OmitRequestBody: true,

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
			ExpectedCount:         0,
		},
		{
			Name:     "broken db",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			OmitRequestBody:  true,
			SimulateBrokenDB: true,

			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
			ExpectedCount:         0,
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadMultipleFixtures([]string{
				"../../test/fixtures/common",
				"../../test/fixtures/admin_router",
			})
			s.Require().NoError(err)

			adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)

			var req *http.Request
			if currentTest.OmitRequestBody {
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/tenants/%s/users", currentTest.TenantID), nil)
			} else {
				body, err := json.Marshal(currentTest.RequestBody)
				s.Require().NoError(err)

				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/tenants/%s/users", currentTest.TenantID), bytes.NewReader(body))
			}
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
				var responseBody []response.UserListDto
				err = json.Unmarshal(rec.Body.Bytes(), &responseBody)
				s.Require().NoError(err)

				s.Assert().Len(responseBody, currentTest.ExpectedCount)
			}
		})
	}
}

func (s *adminSuite) TestAdminRouter_Users_Get() {
	s.SkipOnShort()

	tests := []struct {
		Name     string
		TenantID string
		UserID   string

		SimulateBrokenDB bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
		ExpectedUser          response.UserGetDto
	}{
		{
			Name:     "success",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserID:   "b4fc06d2-2651-47e9-b1c3-3ba19ade9375",

			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `"id":"b4fc06d2-2651-47e9-b1c3-3ba19ade9375"`,
			ExpectedUser: response.UserGetDto{
				UserListDto: response.UserListDto{
					ID:          uuid.FromStringOrNil("b4fc06d2-2651-47e9-b1c3-3ba19ade9375"),
					UserID:      "test-passkey",
					Name:        "passkey",
					Icon:        "",
					DisplayName: "Test Passkey",
				},
				Credentials:  []publicResponse.CredentialDto{},
				Transactions: []publicResponse.TransactionDto{},
			},
		},
		{
			Name:     "unknown tenant",
			TenantID: "00000000-0000-0000-0000-000000000000",
			UserID:   "b4fc06d2-2651-47e9-b1c3-3ba19ade9375",

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:     "malformed tenant",
			TenantID: "malformed",
			UserID:   "b4fc06d2-2651-47e9-b1c3-3ba19ade9375",

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:     "unknown user",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserID:   "00000000-0000-0000-0000-000000000000",

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "user not found",
		},
		{
			Name:     "malformed user",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserID:   "malformed",

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "user_id must be a valid uuid4",
		},
		{
			Name:     "broken db",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserID:   "b4fc06d2-2651-47e9-b1c3-3ba19ade9375",

			SimulateBrokenDB: true,

			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadMultipleFixtures([]string{
				"../../test/fixtures/common",
				"../../test/fixtures/admin_router",
			})
			s.Require().NoError(err)

			adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)

			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/tenants/%s/users/%s", currentTest.TenantID, currentTest.UserID), nil)
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
				var responseBody response.UserGetDto
				err = json.Unmarshal(rec.Body.Bytes(), &responseBody)
				s.Require().NoError(err)

				s.Assert().Equal(currentTest.ExpectedUser, responseBody)
			}
		})
	}
}

func (s *adminSuite) TestAdminRouter_Users_Remove() {
	s.SkipOnShort()

	tests := []struct {
		Name     string
		TenantID string
		UserID   string

		SimulateBrokenDB bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:     "success",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserID:   "b4fc06d2-2651-47e9-b1c3-3ba19ade9375",

			ExpectedStatusCode:    http.StatusNoContent,
			ExpectedStatusMessage: "",
		},
		{
			Name:     "unknown tenant",
			TenantID: "00000000-0000-0000-0000-000000000000",
			UserID:   "b4fc06d2-2651-47e9-b1c3-3ba19ade9375",

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:     "malformed tenant",
			TenantID: "malformed",
			UserID:   "b4fc06d2-2651-47e9-b1c3-3ba19ade9375",

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:     "unknown user",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserID:   "00000000-0000-0000-0000-000000000000",

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "user not found",
		},
		{
			Name:     "malformed user",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserID:   "malformed",

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "user_id must be a valid uuid4",
		},
		{
			Name:     "broken db",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserID:   "b4fc06d2-2651-47e9-b1c3-3ba19ade9375",

			SimulateBrokenDB: true,

			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadMultipleFixtures([]string{
				"../../test/fixtures/common",
				"../../test/fixtures/admin_router",
			})
			s.Require().NoError(err)

			oldCount, err := s.Storage.GetWebauthnUserPersister(nil).Count(uuid.FromStringOrNil(currentTest.TenantID))
			s.Require().NoError(err)

			adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)

			req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/tenants/%s/users/%s", currentTest.TenantID, currentTest.UserID), nil)
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDB {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			adminRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)

			if rec.Code == http.StatusNoContent {
				usr, err := s.Storage.GetWebauthnUserPersister(nil).GetById(uuid.FromStringOrNil(currentTest.UserID))
				s.Require().NoError(err)

				s.Assert().Empty(usr)

				newCount, err := s.Storage.GetWebauthnUserPersister(nil).Count(uuid.FromStringOrNil(currentTest.TenantID))
				s.Require().NoError(err)

				s.Assert().Greater(oldCount, newCount)
			}
		})
	}
}
