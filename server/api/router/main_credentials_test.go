package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/api/dto/response"
	"github.com/teamhanko/passkey-server/config"
	"net/http"
	"net/http/httptest"
)

func (s *mainRouterSuite) TestMainRouter_ListCredentials() {
	s.SkipOnShort()

	tests := []struct {
		Name string

		TenantId    string
		ApiKey      string
		RequestBody interface{}

		SkipApiKey       bool
		SkipBody         bool
		SimulateBrokenDb bool

		ExpectedStatusCode   int
		ExpectedErrorMessage string
	}{
		{
			Name:                 "success",
			TenantId:             "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:               "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:          request.ListCredentialsDto{UserId: "test-passkey"},
			ExpectedStatusCode:   http.StatusOK,
			ExpectedErrorMessage: "",
		},
		{
			Name:                 "missing api key",
			TenantId:             "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody:          request.ListCredentialsDto{UserId: "test-passkey"},
			SkipApiKey:           true,
			ExpectedStatusCode:   http.StatusUnauthorized,
			ExpectedErrorMessage: "The api key is invalid",
		},
		{
			Name:                 "invalid api key",
			TenantId:             "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:               "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg",
			RequestBody:          request.ListCredentialsDto{UserId: "test-passkey"},
			SkipApiKey:           true,
			ExpectedStatusCode:   http.StatusUnauthorized,
			ExpectedErrorMessage: "The api key is invalid",
		},
		{
			Name:                 "tenant not found",
			TenantId:             "00000000-0000-0000-0000-000000000000",
			ApiKey:               "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:          request.ListCredentialsDto{UserId: "test-passkey"},
			ExpectedStatusCode:   http.StatusNotFound,
			ExpectedErrorMessage: "tenant not found",
		},
		{
			Name:                 "invalid tenant",
			TenantId:             "malformed",
			ApiKey:               "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:          request.ListCredentialsDto{UserId: "test-passkey"},
			ExpectedStatusCode:   http.StatusBadRequest,
			ExpectedErrorMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:                 "user not found",
			TenantId:             "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:               "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:          request.ListCredentialsDto{UserId: "not_found"},
			ExpectedStatusCode:   http.StatusNotFound,
			ExpectedErrorMessage: "User not found",
		},
		{
			Name:                 "user not found in tenant",
			TenantId:             "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:               "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:          request.ListCredentialsDto{UserId: "not_found"},
			ExpectedStatusCode:   http.StatusNotFound,
			ExpectedErrorMessage: "User not found",
		},
		{
			Name:     "malformed body",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: struct {
				Lorem string
			}{Lorem: "Ipsum"},
			ExpectedStatusCode:   http.StatusBadRequest,
			ExpectedErrorMessage: "UserId is a required field",
		},
		{
			Name:                 "missing body",
			TenantId:             "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:               "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			SkipBody:             true,
			ExpectedStatusCode:   http.StatusBadRequest,
			ExpectedErrorMessage: "UserId is a required field",
		},
		{
			Name:                 "broken db",
			TenantId:             "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:               "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:          request.ListCredentialsDto{UserId: "test-passkey"},
			SimulateBrokenDb:     true,
			ExpectedStatusCode:   http.StatusInternalServerError,
			ExpectedErrorMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {

			err := s.LoadMultipleFixtures([]string{
				"../../test/fixtures/common",
				"../../test/fixtures/main_router/credentials",
			})
			s.Require().NoError(err)

			mainRouter := NewMainRouter(&config.Config{}, s.Storage, nil)

			path := fmt.Sprintf("/%s/credentials", currentTest.TenantId)
			var req *http.Request

			if !currentTest.SkipBody {
				jsonBody, err := json.Marshal(currentTest.RequestBody)
				s.Require().NoError(err)

				req = httptest.NewRequest(http.MethodGet, path, bytes.NewReader(jsonBody))
			} else {
				req = httptest.NewRequest(http.MethodGet, path, nil)
			}
			req.Header.Set("Content-Type", "application/json")

			if !currentTest.SkipApiKey {
				req.Header.Set("apiKey", currentTest.ApiKey)
			}

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDb {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			mainRouter.ServeHTTP(rec, req)

			if rec.Code == http.StatusOK {
				var credentials response.CredentialDtoList
				s.NoError(json.Unmarshal(rec.Body.Bytes(), &credentials))
				s.Equal(1, len(credentials))
			} else {
				if s.Equal(currentTest.ExpectedStatusCode, rec.Code) {
					s.Assert().Contains(rec.Body.String(), currentTest.ExpectedErrorMessage)
				}
			}
		})
	}
}

func (s *mainRouterSuite) TestMainRouter_UpdateCredentials() {
	s.SkipOnShort()

	tests := []struct {
		Name string

		TenantId       string
		CredentialId   string
		ApiKey         string
		CredentialName string
		RequestBody    interface{}

		SkipApiKey       bool
		SkipBody         bool
		SimulateBrokenDb bool

		ExpectedStatusCode   int
		ExpectedErrorMessage string
	}{
		{
			Name:           "success",
			TenantId:       "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			CredentialId:   "kV8CJn6hoh2wIhKyw6x2fI9nGiEN5Sdczhx3o6ejgcY",
			CredentialName: "Ipsum",
			ApiKey:         "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: struct {
				Name string `json:"name"`
			}{
				Name: "Ipsum",
			},
			ExpectedStatusCode:   http.StatusNoContent,
			ExpectedErrorMessage: "",
		},
		{
			Name:           "missing api key",
			TenantId:       "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			CredentialId:   "kV8CJn6hoh2wIhKyw6x2fI9nGiEN5Sdczhx3o6ejgcY",
			CredentialName: "Ipsum",
			SkipApiKey:     true,
			RequestBody: struct {
				Name string `json:"name"`
			}{
				Name: "Ipsum",
			},
			ExpectedStatusCode:   http.StatusUnauthorized,
			ExpectedErrorMessage: "The api key is invalid",
		},
		{
			Name:           "invalid api key",
			TenantId:       "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			CredentialId:   "kV8CJn6hoh2wIhKyw6x2fI9nGiEN5Sdczhx3o6ejgcY",
			CredentialName: "Ipsum",
			ApiKey:         "invalid",
			RequestBody: struct {
				Name string `json:"name"`
			}{
				Name: "Ipsum",
			},
			ExpectedStatusCode:   http.StatusUnauthorized,
			ExpectedErrorMessage: "The api key is invalid",
		},
		{
			Name:           "tenant not found",
			TenantId:       "00000000-0000-0000-0000-000000000000",
			CredentialId:   "kV8CJn6hoh2wIhKyw6x2fI9nGiEN5Sdczhx3o6ejgcY",
			CredentialName: "Ipsum",
			ApiKey:         "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: struct {
				Name string `json:"name"`
			}{
				Name: "Ipsum",
			},
			ExpectedStatusCode:   http.StatusNotFound,
			ExpectedErrorMessage: "tenant not found",
		},
		{
			Name:           "malformed tenant id",
			TenantId:       "malformed",
			CredentialId:   "kV8CJn6hoh2wIhKyw6x2fI9nGiEN5Sdczhx3o6ejgcY",
			CredentialName: "Ipsum",
			ApiKey:         "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: struct {
				Name string `json:"name"`
			}{
				Name: "Ipsum",
			},
			ExpectedStatusCode:   http.StatusBadRequest,
			ExpectedErrorMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:           "credential not found",
			TenantId:       "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			CredentialId:   "4Yx3hvHKiJgqq3BRsmY-5zDzS52GSKcQpWumEl5aF-E",
			CredentialName: "Ipsum",
			ApiKey:         "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: struct {
				Name string `json:"name"`
			}{
				Name: "Ipsum",
			},
			ExpectedStatusCode:   http.StatusNotFound,
			ExpectedErrorMessage: "credential with id '4Yx3hvHKiJgqq3BRsmY-5zDzS52GSKcQpWumEl5aF-E' not found",
		},
		{
			Name:           "invalid request body",
			TenantId:       "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			CredentialId:   "kV8CJn6hoh2wIhKyw6x2fI9nGiEN5Sdczhx3o6ejgcY",
			CredentialName: "Ipsum",
			ApiKey:         "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: struct {
				Lorem string `json:"lorem"`
			}{
				Lorem: "Ipsum",
			},
			ExpectedStatusCode:   http.StatusBadRequest,
			ExpectedErrorMessage: "name is a required field",
		},
		{
			Name:                 "missing request body",
			TenantId:             "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			CredentialId:         "kV8CJn6hoh2wIhKyw6x2fI9nGiEN5Sdczhx3o6ejgcY",
			CredentialName:       "Ipsum",
			ApiKey:               "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			SkipBody:             true,
			ExpectedStatusCode:   http.StatusBadRequest,
			ExpectedErrorMessage: "name is a required field",
		},
		{
			Name:           "broken db",
			TenantId:       "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			CredentialId:   "kV8CJn6hoh2wIhKyw6x2fI9nGiEN5Sdczhx3o6ejgcY",
			CredentialName: "Ipsum",
			ApiKey:         "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: struct {
				Name string `json:"name"`
			}{
				Name: "Ipsum",
			},
			SimulateBrokenDb:     true,
			ExpectedStatusCode:   http.StatusInternalServerError,
			ExpectedErrorMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {

			err := s.LoadMultipleFixtures([]string{
				"../../test/fixtures/common",
				"../../test/fixtures/main_router/credentials",
			})
			s.Require().NoError(err)

			mainRouter := NewMainRouter(&config.Config{}, s.Storage, nil)

			path := fmt.Sprintf("/%s/credentials/%s", currentTest.TenantId, currentTest.CredentialId)
			var req *http.Request

			testCred, err := s.Storage.GetWebauthnCredentialPersister(nil).Get(currentTest.CredentialId, uuid.FromStringOrNil(currentTest.TenantId))
			s.Require().NoError(err)

			if !currentTest.SkipBody {
				jsonBody, err := json.Marshal(currentTest.RequestBody)
				s.Require().NoError(err)

				req = httptest.NewRequest(http.MethodPatch, path, bytes.NewReader(jsonBody))
			} else {
				req = httptest.NewRequest(http.MethodPatch, path, nil)
			}
			req.Header.Set("Content-Type", "application/json")

			if !currentTest.SkipApiKey {
				req.Header.Set("apiKey", currentTest.ApiKey)
			}

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDb {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			mainRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			if rec.Code == http.StatusNoContent {
				updatedCred, err := s.Storage.GetWebauthnCredentialPersister(nil).Get(currentTest.CredentialId, uuid.FromStringOrNil(currentTest.TenantId))
				s.Require().NoError(err)

				s.Assert().NotEqual(*testCred.Name, *updatedCred.Name)
				s.Assert().Equal(currentTest.CredentialName, *updatedCred.Name)
				s.Assert().True(updatedCred.UpdatedAt.After(testCred.UpdatedAt))
			} else {
				s.Assert().Contains(rec.Body.String(), currentTest.ExpectedErrorMessage)
			}
		})
	}
}

func (s *mainRouterSuite) TestMainRouter_DeleteCredentials() {
	s.SkipOnShort()

	tests := []struct {
		Name string

		TenantId     string
		CredentialId string
		ApiKey       string

		SkipApiKey       bool
		SimulateBrokenDb bool

		ExpectedStatusCode   int
		ExpectedErrorMessage string
	}{
		{
			Name:                 "success",
			TenantId:             "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			CredentialId:         "kV8CJn6hoh2wIhKyw6x2fI9nGiEN5Sdczhx3o6ejgcY",
			ApiKey:               "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			ExpectedStatusCode:   http.StatusNoContent,
			ExpectedErrorMessage: "",
		},
		{
			Name:                 "missing api key",
			TenantId:             "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			CredentialId:         "kV8CJn6hoh2wIhKyw6x2fI9nGiEN5Sdczhx3o6ejgcY",
			SkipApiKey:           true,
			ExpectedStatusCode:   http.StatusUnauthorized,
			ExpectedErrorMessage: "The api key is invalid",
		},
		{
			Name:                 "invalid api key",
			TenantId:             "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			CredentialId:         "kV8CJn6hoh2wIhKyw6x2fI9nGiEN5Sdczhx3o6ejgcY",
			ApiKey:               "invalid",
			ExpectedStatusCode:   http.StatusUnauthorized,
			ExpectedErrorMessage: "The api key is invalid",
		},
		{
			Name:                 "tenant not found",
			TenantId:             "00000000-0000-0000-0000-000000000000",
			CredentialId:         "kV8CJn6hoh2wIhKyw6x2fI9nGiEN5Sdczhx3o6ejgcY",
			ApiKey:               "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			ExpectedStatusCode:   http.StatusNotFound,
			ExpectedErrorMessage: "tenant not found",
		},
		{
			Name:                 "invalid tenant",
			TenantId:             "malformed",
			CredentialId:         "kV8CJn6hoh2wIhKyw6x2fI9nGiEN5Sdczhx3o6ejgcY",
			ApiKey:               "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			ExpectedStatusCode:   http.StatusBadRequest,
			ExpectedErrorMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:                 "credential  not found",
			TenantId:             "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			CredentialId:         "00000000-0000-0000-0000-000000000000",
			ApiKey:               "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			ExpectedStatusCode:   http.StatusNotFound,
			ExpectedErrorMessage: "credential with id '00000000-0000-0000-0000-000000000000' not found",
		},
		{
			Name:                 "existing credential for another tenant not found",
			TenantId:             "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			CredentialId:         "4Yx3hvHKiJgqq3BRsmY-5zDzS52GSKcQpWumEl5aF-E",
			ApiKey:               "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			ExpectedStatusCode:   http.StatusNotFound,
			ExpectedErrorMessage: "credential with id '4Yx3hvHKiJgqq3BRsmY-5zDzS52GSKcQpWumEl5aF-E' not found",
		},
		{
			Name:                 "broken db",
			TenantId:             "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			CredentialId:         "kV8CJn6hoh2wIhKyw6x2fI9nGiEN5Sdczhx3o6ejgcY",
			ApiKey:               "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			ExpectedStatusCode:   http.StatusInternalServerError,
			SimulateBrokenDb:     true,
			ExpectedErrorMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {

			err := s.LoadMultipleFixtures([]string{
				"../../test/fixtures/common",
				"../../test/fixtures/main_router/credentials",
			})
			s.Require().NoError(err)

			mainRouter := NewMainRouter(&config.Config{}, s.Storage, nil)

			req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/%s/credentials/%s", currentTest.TenantId, currentTest.CredentialId), nil)
			req.Header.Set("Content-Type", "application/json")

			if !currentTest.SkipApiKey {
				req.Header.Set("apiKey", currentTest.ApiKey)
			}

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDb {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			mainRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			if rec.Code == http.StatusNoContent {
				updatedCred, err := s.Storage.GetWebauthnCredentialPersister(nil).Get(currentTest.CredentialId, uuid.FromStringOrNil(currentTest.TenantId))
				s.Require().NoError(err)

				s.Assert().Nil(updatedCred)
			} else {
				s.Assert().Contains(rec.Body.String(), currentTest.ExpectedErrorMessage)
			}
		})
	}
}
