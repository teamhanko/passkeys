package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/api/dto/response"
	"github.com/teamhanko/passkey-server/config"
	"net/http"
	"net/http/httptest"
	"strings"
)

func (s *mainRouterSuite) TestMainRouter_Transaction_List() {
	s.SkipOnShort()

	tests := []struct {
		Name     string
		TenantId string
		UserId   string
		ApiKey   string

		SkipApiKey       bool
		SimulateBrokenDB bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:                  "success",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "b4fc06d2-2651-47e9-b1c3-3ba19ade9375",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `[{"id":"`,
		},
		{
			Name:                  "missing user id",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "Not Found",
		},
		{
			Name:                  "malformed user id",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "malformed",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "invalid user id",
		},
		{
			Name:                  "unknown user",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "000000000-0000-0000-0000-000000000000",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "invalid user id",
		},
		{
			Name:                  "missing api key",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "b4fc06d2-2651-47e9-b1c3-3ba19ade9375",
			SkipApiKey:            true,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "The api key is invalid",
		},
		{
			Name:                  "malformed api key",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "b4fc06d2-2651-47e9-b1c3-3ba19ade9375",
			ApiKey:                "malformed",
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "The api key is invalid",
		},
		{
			Name:                  "malformed tenant",
			TenantId:              "malformed",
			UserId:                "b4fc06d2-2651-47e9-b1c3-3ba19ade9375",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:                  "missing tenant",
			UserId:                "b4fc06d2-2651-47e9-b1c3-3ba19ade9375",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:                  "broken db",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			SimulateBrokenDB:      true,
			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadMultipleFixtures([]string{
				"../../test/fixtures/common",
				"../../test/fixtures/main_router/transaction",
			})
			s.Require().NoError(err)

			mainRouter := NewMainRouter(&config.Config{}, s.Storage, nil)

			if currentTest.SimulateBrokenDB {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/%s/transaction/%s", currentTest.TenantId, currentTest.UserId), nil)

			if !currentTest.SkipApiKey {
				req.Header.Set("apiKey", currentTest.ApiKey)
			}

			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mainRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)

			if rec.Code == http.StatusOK {
				var transactions []response.TransactionDto
				err = json.Unmarshal(rec.Body.Bytes(), &transactions)
				s.Require().NoError(err)

				s.Assert().Len(transactions, 2)
			}
		})
	}
}

func (s *mainRouterSuite) TestMainRouter_Transaction_Init() {
	s.SkipOnShort()

	tests := []struct {
		Name        string
		TenantId    string
		UserId      string
		ApiKey      string
		RequestBody interface{}

		SkipApiKey       bool
		SimulateBrokenDB bool
		OmitRequestBody  bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:     "success",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:   "test-passkey",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: request.InitTransactionDto{
				UserId:        "test-passkey",
				TransactionId: "00000001-0001-0001-0001-000000000001",
				TransactionData: struct {
					Lorem string `json:"lorem"`
				}{
					Lorem: "Ipsum",
				},
			},
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `"publicKey":{"challenge":`,
		},
		{
			Name:     "missing user id",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:   "test-passkey",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: request.InitTransactionDto{
				TransactionId: "00000001-0001-0001-0001-000000000001",
				TransactionData: struct {
					Lorem string `json:"lorem"`
				}{
					Lorem: "Ipsum",
				},
			},
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "user_id is a required field",
		},
		{
			Name:     "missing transaction id",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:   "test-passkey",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: request.InitTransactionDto{
				UserId: "test-passkey",
				TransactionData: struct {
					Lorem string `json:"lorem"`
				}{
					Lorem: "Ipsum",
				},
			},
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "transaction_id is a required field",
		},
		{
			Name:     "transaction id to long",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:   "test-passkey",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: request.InitTransactionDto{
				UserId:        "test-passkey",
				TransactionId: "00000001-0001-0001-0001-000000000001--00000001-0001-0001-0001-000000000001--00000001-0001-0001-0001-000000000001--00000001-0001-0001-0001-000000000001",
				TransactionData: struct {
					Lorem string `json:"lorem"`
				}{
					Lorem: "Ipsum",
				},
			},
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "transaction_id cannot have more than 128 entries",
		},
		{
			Name:     "missing transaction data",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:   "test-passkey",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: request.InitTransactionDto{
				UserId:        "test-passkey",
				TransactionId: "00000001-0001-0001-0001-000000000001",
			},
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "transaction_data is a required field",
		},
		{
			Name:     "malformed request body",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:   "test-passkey",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: struct {
				Lorem string `json:"lorem"`
			}{
				Lorem: "malformed",
			},
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "user_id is a required field and transaction_id is a required field and transaction_data is a required field",
		},
		{
			Name:                  "missing request body",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			OmitRequestBody:       true,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "user_id is a required field and transaction_id is a required field and transaction_data is a required field",
		},
		{
			Name:     "missing api key",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:   "test-passkey",
			RequestBody: request.InitTransactionDto{
				UserId:        "test-passkey",
				TransactionId: "00000001-0001-0001-0001-000000000001",
				TransactionData: struct {
					Lorem string `json:"lorem"`
				}{
					Lorem: "Ipsum",
				},
			},
			SkipApiKey:            true,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "The api key is invalid",
		},
		{
			Name:     "unknown user",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:   "4Yx3hvHKiJgqq3BRsmY-5zDzS52GSKcQpWumEl5aF-E",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: request.InitTransactionDto{
				UserId:        "4Yx3hvHKiJgqq3BRsmY-5zDzS52GSKcQpWumEl5aF-E",
				TransactionId: "00000001-0001-0001-0001-000000000001",
				TransactionData: struct {
					Lorem string `json:"lorem"`
				}{
					Lorem: "Ipsum",
				},
			},
			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "unable to find user",
		},
		{
			Name:     "malformed tenant",
			TenantId: "malformed",
			UserId:   "test-passkey",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: request.InitTransactionDto{
				UserId:        "test-passkey",
				TransactionId: "00000001-0001-0001-0001-000000000001",
				TransactionData: struct {
					Lorem string `json:"lorem"`
				}{
					Lorem: "Ipsum",
				},
			},
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:   "missing tenant",
			UserId: "test-passkey",
			ApiKey: "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: request.InitTransactionDto{
				UserId:        "test-passkey",
				TransactionId: "00000001-0001-0001-0001-000000000001",
				TransactionData: struct {
					Lorem string `json:"lorem"`
				}{
					Lorem: "Ipsum",
				},
			},
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:     "broken db",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:   "test-passkey",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: request.InitTransactionDto{
				UserId:        "test-passkey",
				TransactionId: "00000001-0001-0001-0001-000000000001",
				TransactionData: struct {
					Lorem string `json:"lorem"`
				}{
					Lorem: "Ipsum",
				},
			},
			SimulateBrokenDB:      true,
			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadMultipleFixtures([]string{
				"../../test/fixtures/common",
				"../../test/fixtures/main_router/transaction",
			})
			s.Require().NoError(err)

			mainRouter := NewMainRouter(&config.Config{}, s.Storage, nil)

			if currentTest.SimulateBrokenDB {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			var req *http.Request
			if currentTest.OmitRequestBody {
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/transaction/initialize", currentTest.TenantId), nil)
			} else {
				body, err := json.Marshal(currentTest.RequestBody)
				s.Require().NoError(err)

				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/transaction/initialize", currentTest.TenantId), bytes.NewReader(body))
			}

			if !currentTest.SkipApiKey {
				req.Header.Set("apiKey", currentTest.ApiKey)
			}

			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mainRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)

			if rec.Code == http.StatusOK {
				var ca protocol.CredentialAssertion
				err = json.Unmarshal(rec.Body.Bytes(), &ca)
				s.Require().NoError(err)

				sessionData, err := s.Storage.GetWebauthnSessionDataPersister(nil).GetByChallenge(ca.Response.Challenge.String(), uuid.FromStringOrNil(currentTest.TenantId))
				s.Require().NoError(err)
				s.Assert().False(sessionData.IsDiscoverable)
			}
		})
	}
}

func (s *mainRouterSuite) TestMainRouter_Transaction_Finish() {
	s.SkipOnShort()

	tests := []struct {
		Name        string
		TenantId    string
		UserId      string
		ApiKey      string
		RequestBody string

		SkipApiKey       bool
		SimulateBrokenDB bool
		OmitRequestBody  bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:                  "success",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey-discover",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"9QEeUpkDJqEy4sa7JUe1PjpYMSO4nQQNN9X-kK0wTFQ","rawId":"9QEeUpkDJqEy4sa7JUe1PjpYMSO4nQQNN9X-kK0wTFQ","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiRHlwQUlpODVuclVlWkR4THltMkNqeEhRRE1kRzNNTmRiaU13eXVKZ0VDZmh5ZVJsY3dDMEV5Z1ZFb2FEbDkxYlJVM1hLYWMwSnZLbU5oMi1XM01MV3ciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEYCIQDUYA_5bvdEf0LT5Xq2qMQvEKUflVBd5pcl2wkz87KlYgIhAO3XNLPOSwffYdnwht5h3pJTexxc-KwuLpsCSsWCfbLc","userHandle":"dGVzdC1wYXNza2V5"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `{"token":"`,
		},
		{
			Name:                  "wrong tenant",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396f",
			UserId:                "a1B2c3D4",
			ApiKey:                "bXta7uDpBt6nBn4j2sX7vm1KGqp7ma9GXPx835IiEdnJxWu_HA-rCdmdTk7I9oYQnYo4MebHkQ3khSosXJ6y5A==",
			RequestBody:           `{"type":"public-key","id":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","rawId":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoieFVpRmNLdlY3V1RQRW1FdWdTVERkWFpkcjc2RnBabC0ycVpDczBodmFodyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCICR40uXfNpSwlTIxuNBWRvRU8UTMFJcsUi9WCNzDhKqrAiEA87nlHkGPNYVoFvDe3NeODAj_EQ7auL00G8kmYjvq62U","userHandle":"YTFCMmMzRDQ"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "failed to get transaction data",
		},
		{
			Name:                  "tenant not found",
			TenantId:              "00000000-0000-0000-0000-000000000000",
			UserId:                "a1B2c3D4",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","rawId":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoieFVpRmNLdlY3V1RQRW1FdWdTVERkWFpkcjc2RnBabC0ycVpDczBodmFodyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCICR40uXfNpSwlTIxuNBWRvRU8UTMFJcsUi9WCNzDhKqrAiEA87nlHkGPNYVoFvDe3NeODAj_EQ7auL00G8kmYjvq62U","userHandle":"YTFCMmMzRDQ"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:                  "malformed tenant",
			TenantId:              "malformed",
			UserId:                "a1B2c3D4",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","rawId":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoieFVpRmNLdlY3V1RQRW1FdWdTVERkWFpkcjc2RnBabC0ycVpDczBodmFodyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCICR40uXfNpSwlTIxuNBWRvRU8UTMFJcsUi9WCNzDhKqrAiEA87nlHkGPNYVoFvDe3NeODAj_EQ7auL00G8kmYjvq62U","userHandle":"YTFCMmMzRDQ"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:                  "success with missing api key",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			RequestBody:           `{"type":"public-key","id":"af5_nnDDP1eN3BPORT5cDfbSwfiPGy-9j85KdB3WQ6w","rawId":"af5_nnDDP1eN3BPORT5cDfbSwfiPGy-9j85KdB3WQ6w","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVWljUDNmb0dQZmFoZF9kdVlHbnVCeVNtVldhUGw5VkNOSzdCNDJpM2Z4ayIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCIF-LTHRYEHX4r9pWj39-o2NglZV8U3wGvOkmT-KH2ecjAiEA_1dYDRgiJsx7_1i9kIX8YWqzUlOzzHlz9HJgj0dGPmQ","userHandle":"dGVzdC1wYXNza2V5LWRpc2NvdmVy"},"clientExtensionResults":{}}`,
			SkipApiKey:            true,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "The api key is invalid",
		},
		{
			Name:                  "malformed api key",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			ApiKey:                "malformed",
			RequestBody:           `{"type":"public-key","id":"9QEeUpkDJqEy4sa7JUe1PjpYMSO4nQQNN9X-kK0wTFQ","rawId":"9QEeUpkDJqEy4sa7JUe1PjpYMSO4nQQNN9X-kK0wTFQ","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiMEw3bTUyTmVEM0xpMXFteVhUMVp4Mk5nQ1lnNEstQTNiamQ4TzA5dmxVMCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCIQCzxd6TRox_Dx4lOPrLYpfj4umnx4aNPZ1Tg7QA4OZtWwIgMSPL_oMUENDy1I5rGSmUjNs73eDtOVTq_D6wNs4qeDE","userHandle":"dGVzdC1wYXNza2V5"},"clientExtensionResults":{}}`,
			SkipApiKey:            false,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "The api key is invalid",
		},
		{
			Name:                  "wrong user handle",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "a1B2c3D4",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"9QEeUpkDJqEy4sa7JUe1PjpYMSO4nQQNN9X-kK0wTFQ","rawId":"9QEeUpkDJqEy4sa7JUe1PjpYMSO4nQQNN9X-kK0wTFQ","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiRHlwQUlpODVuclVlWkR4THltMkNqeEhRRE1kRzNNTmRiaU13eXVKZ0VDZmh5ZVJsY3dDMEV5Z1ZFb2FEbDkxYlJVM1hLYWMwSnZLbU5oMi1XM01MV3ciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEYCIQDUYA_5bvdEf0LT5Xq2qMQvEKUflVBd5pcl2wkz87KlYgIhAO3XNLPOSwffYdnwht5h3pJTexxc-KwuLpsCSsWCfbLc","userHandle":"dGVzdA=="},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "failed to get user by user handle",
		},
		{
			Name:                  "wrong credential",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "a1B2c3D4",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"9QEeUpkDJqEy4sa7JUe1PjpYMSO4nQQNN9X-kK0wTFQ","rawId":"9QEeUpkDJqEy4sa7JUe1PjpYMSO4nQQNN9X-kK0wTFQ","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZGNqSmJtSDh3eHVCZ1p3QXdzeF84WFFuSFgxYlJCVjFoWHo3TDJ0UF91QSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCIG9UopCXxa8o_Lk_-fJRgzV-6Bi8-DlTjkvAQYFpKZliAiEAgbZe4h24DHpzqKhk84LuQJmOHiXAuQz67fbo8DGJZZ8","userHandle":"dGVzdC1wYXNza2V5LWRpc2NvdmVy"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "received challenge does not match with any stored one",
		},
		{
			Name:                  "fail to use mfa credential",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "mfa-test",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"x_ofcjYOjqIIfJWBTlWbk62Bi37v-myfpr1Dhrs0-VQ","rawId":"x_ofcjYOjqIIfJWBTlWbk62Bi37v-myfpr1Dhrs0-VQ","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiRHlwQUlpODVuclVlWkR4THltMkNqeEhRRE1kRzNNTmRiaU13eXVKZ0VDZmh5ZVJsY3dDMEV5Z1ZFb2FEbDkxYlJVM1hLYWMwSnZLbU5oMi1XM01MV3ciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEYCIQDUYA_5bvdEf0LT5Xq2qMQvEKUflVBd5pcl2wkz87KlYgIhAO3XNLPOSwffYdnwht5h3pJTexxc-KwuLpsCSsWCfbLc","userHandle":"dGVzdC1wYXNza2V5"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "Unable to find the credential for the returned credential ID",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadMultipleFixtures([]string{
				"../../test/fixtures/common",
				"../../test/fixtures/main_router/transaction",
			})
			s.Require().NoError(err)

			mainRouter := NewMainRouter(&config.Config{}, s.Storage, nil)

			if currentTest.SimulateBrokenDB {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			var req *http.Request
			if currentTest.OmitRequestBody {
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/transaction/finalize", currentTest.TenantId), nil)
			} else {
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/transaction/finalize", currentTest.TenantId), strings.NewReader(currentTest.RequestBody))
			}

			if !currentTest.SkipApiKey {
				req.Header.Set("apiKey", currentTest.ApiKey)
			}

			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mainRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)
		})
	}
}
