package router

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/mapper"
	"github.com/teamhanko/passkey-server/test/helper"
	"net/http"
	"net/http/httptest"
	"strings"
)

func (s *mainRouterSuite) TestMainRouter_Mfa_Registration_Init() {
	s.SkipOnShort()

	tests := []struct {
		Name     string
		TenantId string
		ApiKey   string
		UserId   string

		RequestBody interface{}

		SkipApiKey       bool
		OmitRequestBody  bool
		SimulateBrokenDB bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:     "success",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			UserId:   "Lorem",
			RequestBody: request.InitRegistrationDto{
				UserId:      "Lorem",
				Username:    "Ipsum",
				DisplayName: helper.ToPointer("Lorem Ipsum"),
				Icon:        helper.ToPointer("http://localhost/my/icon.png"),
			},

			ExpectedStatusCode: http.StatusOK,
		},
		{
			Name:     "success without optional parameters",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			UserId:   "Lorem",
			RequestBody: request.InitRegistrationDto{
				UserId:   "Lorem",
				Username: "Ipsum",
			},

			ExpectedStatusCode: http.StatusOK,
		},
		{
			Name:     "tenant not found",
			TenantId: "00000000-0000-0000-0000-000000000000",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: request.InitRegistrationDto{
				UserId:      "lorem",
				Username:    "Ipsum",
				DisplayName: helper.ToPointer("Lorem Ipsum"),
				Icon:        helper.ToPointer("http://localhost/my/icon.png"),
			},

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:     "wrong tenant",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396f",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: request.InitRegistrationDto{
				UserId:      "lorem",
				Username:    "Ipsum",
				DisplayName: helper.ToPointer("Lorem Ipsum"),
				Icon:        helper.ToPointer("http://localhost/my/icon.png"),
			},

			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "The api key is invalid",
		},
		{
			Name:       "missing api key",
			TenantId:   "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			SkipApiKey: true,
			RequestBody: request.InitRegistrationDto{
				UserId:      "lorem",
				Username:    "Ipsum",
				DisplayName: helper.ToPointer("Lorem Ipsum"),
				Icon:        helper.ToPointer("http://localhost/my/icon.png"),
			},

			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "The api key is invalid",
		},
		{
			Name:     "malformed api key",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:   "malformed",
			RequestBody: request.InitRegistrationDto{
				UserId:      "lorem",
				Username:    "Ipsum",
				DisplayName: helper.ToPointer("Lorem Ipsum"),
				Icon:        helper.ToPointer("http://localhost/my/icon.png"),
			},

			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "The api key is invalid",
		},
		{
			Name:     "display_name too long",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: request.InitRegistrationDto{
				UserId:      "lorem",
				Username:    "Ipsum",
				DisplayName: helper.ToPointer("LSiV5QsqY9Q9oiT03sIUC7imvSYM6UR9X6VtaYxfZyhyIGNrLoxolOunCoOxe8kOAAjEkMQadSezOBFpzdtIIpuceNkyHLc7cXCywx8JkRutyqpqotaUskXyGh78c5NZYcx"),
				Icon:        helper.ToPointer("http://localhost/my/icon.png"),
			},

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "display_name cannot have more than 128 entries",
		},
		{
			Name:     "username too long",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: request.InitRegistrationDto{
				UserId:      "lorem",
				Username:    "LSiV5QsqY9Q9oiT03sIUC7imvSYM6UR9X6VtaYxfZyhyIGNrLoxolOunCoOxe8kOAAjEkMQadSezOBFpzdtIIpuceNkyHLc7cXCywx8JkRutyqpqotaUskXyGh78c5NZYcx",
				DisplayName: helper.ToPointer("Lorem Ipsum"),
				Icon:        helper.ToPointer("http://localhost/my/icon.png"),
			},

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "username cannot have more than 128 entries",
		},
		{
			Name:     "icon must be URL",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: request.InitRegistrationDto{
				UserId:      "lorem",
				Username:    "LSiV5QsqY9Q9oiT03sIUC7imvSYM6UR9X6VtaYxfZyhyIGNrLoxolOunCoOxe8kOAAjEkMQadSezOBFpzdtIIpuceNkyHLc7cXCywx8JkRutyqpqotaUskXyGh78c5NZYcx",
				DisplayName: helper.ToPointer("Lorem Ipsum"),
				Icon:        helper.ToPointer("no-url"),
			},

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "icon must be a valid URL",
		},
		{
			Name:     "malformed body",
			TenantId: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:   "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: struct {
				Lorem string `json:"lorem"`
			}{
				Lorem: "Ipsum",
			},

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "user_id is a required field and username is a required field",
		},
		{
			Name:            "missing body",
			TenantId:        "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:          "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			OmitRequestBody: true,

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "user_id is a required field and username is a required field",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadMultipleFixtures([]string{
				"../../test/fixtures/common",
				"../../test/fixtures/main_router/registration",
			})
			s.Require().NoError(err)

			mainRouter := NewMainRouter(&config.Config{}, s.Storage, nil)

			if currentTest.SimulateBrokenDB {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			var req *http.Request
			if currentTest.OmitRequestBody {
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/mfa/registration/initialize", currentTest.TenantId), nil)
			} else {
				body, err := json.Marshal(currentTest.RequestBody)
				s.Require().NoError(err)

				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/mfa/registration/initialize", currentTest.TenantId), bytes.NewReader(body))
			}

			if !currentTest.SkipApiKey {
				req.Header.Set("apiKey", currentTest.ApiKey)
			}

			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mainRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)

			if rec.Code == http.StatusOK {
				tenant, err := s.Storage.GetTenantPersister(nil).Get(uuid.FromStringOrNil(currentTest.TenantId))
				s.Require().NoError(err)

				creationOptions := protocol.CredentialCreation{}
				err = json.Unmarshal(rec.Body.Bytes(), &creationOptions)
				s.NoError(err)

				uId, err := base64.RawURLEncoding.DecodeString(creationOptions.Response.User.ID.(string))
				s.Require().NoError(err)

				s.NotEmpty(creationOptions.Response.Challenge)
				s.Equal([]byte(currentTest.UserId), uId)
				s.Equal(tenant.Config.WebauthnConfig.RelyingParty.RPId, creationOptions.Response.RelyingParty.ID)
				s.Equal(protocol.ResidentKeyRequirementDiscouraged, creationOptions.Response.AuthenticatorSelection.ResidentKey)
				s.Equal(protocol.VerificationDiscouraged, creationOptions.Response.AuthenticatorSelection.UserVerification)
				s.False(*creationOptions.Response.AuthenticatorSelection.RequireResidentKey)
			} else {
				s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)
			}
		})
	}

}

func (s *mainRouterSuite) TestMainRouter_Mfa_Registration_Finalize() {
	s.SkipOnShort()

	tests := []struct {
		Name        string
		TenantId    string
		UserId      string
		ApiKey      string
		CredName    string
		RequestBody string

		SkipApiKey       bool
		OmitRequestBody  bool
		SimulateBrokenDB bool
		UseAAGUIDMapping bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:                  "success without mapping",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			UserId:                "test-mfa",
			CredName:              "cred-7ylGZMEWkocCJH6zzRx4BW12xu_BjXx2U9cvRTTVsJI",
			RequestBody:           `{"type":"public-key","id":"7ylGZMEWkocCJH6zzRx4BW12xu_BjXx2U9cvRTTVsJI","rawId":"7ylGZMEWkocCJH6zzRx4BW12xu_BjXx2U9cvRTTVsJI","authenticatorAttachment":"cross-platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiaW1FTVp3clNoc3REYm8tVXVWU0xXSkVzX2gyYWhoM3UtTDg2T1hIeXByRSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgOUg2Oxj9_nr0Ecd1QRxNpvyH7X9bqVzCLfMmjADX7ccCIQDdKCLK5pPV8_dtGni9vBaOwo37NtZq1YKyCg5ElHeWUGN4NWOBWQHZMIIB1TCCAXqgAwIBAgIBATAKBggqhkjOPQQDAjBgMQswCQYDVQQGEwJVUzERMA8GA1UECgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMB4XDTE3MDcxNDAyNDAwMFoXDTQ0MDUzMDExNDYyMVowYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1hfmXJUI5kvMVnOsgqZ5naPBRGaCwljEY__99Y39L6Pmw3i1PXlcSk3_tBme3Xhi8jq68CA7S4kRugVpmU4QGjJTAjMAwGA1UdEwEB_wQCMAAwEwYLKwYBBAGC5RwCAQEEBAMCBSAwCgYIKoZIzj0EAwIDSQAwRgIhAMyq3nMojMBhy72bTW_GsKcpTmCnASaUU-XSJFzmPpiKAiEAv2MDR9dsfZWYfkk3MQwRyqIgDKUFr_NbDOcKkOmIv1poYXV0aERhdGFYpEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRQAAAAEBAgMEBQYHCAECAwQFBgcIACDvKUZkwRaShwIkfrPNHHgFbXbG78GNfHZT1y9FNNWwkqUBAgMmIAEhWCC2T8LO1U5gt6dWYinNf0X_imOxyPtSIIqq3-tH0IUB8iJYIC2o7XHv3zDWr2vykXxZWMPybcnXWcAS5oWHDkZmSwqN","transports":["usb"]},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `"token"`,
		},
		{
			Name:                  "success with mapping",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			UserId:                "test-mfa",
			CredName:              "Test Provider",
			RequestBody:           `{"type":"public-key","id":"7ylGZMEWkocCJH6zzRx4BW12xu_BjXx2U9cvRTTVsJI","rawId":"7ylGZMEWkocCJH6zzRx4BW12xu_BjXx2U9cvRTTVsJI","authenticatorAttachment":"cross-platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiaW1FTVp3clNoc3REYm8tVXVWU0xXSkVzX2gyYWhoM3UtTDg2T1hIeXByRSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgOUg2Oxj9_nr0Ecd1QRxNpvyH7X9bqVzCLfMmjADX7ccCIQDdKCLK5pPV8_dtGni9vBaOwo37NtZq1YKyCg5ElHeWUGN4NWOBWQHZMIIB1TCCAXqgAwIBAgIBATAKBggqhkjOPQQDAjBgMQswCQYDVQQGEwJVUzERMA8GA1UECgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMB4XDTE3MDcxNDAyNDAwMFoXDTQ0MDUzMDExNDYyMVowYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1hfmXJUI5kvMVnOsgqZ5naPBRGaCwljEY__99Y39L6Pmw3i1PXlcSk3_tBme3Xhi8jq68CA7S4kRugVpmU4QGjJTAjMAwGA1UdEwEB_wQCMAAwEwYLKwYBBAGC5RwCAQEEBAMCBSAwCgYIKoZIzj0EAwIDSQAwRgIhAMyq3nMojMBhy72bTW_GsKcpTmCnASaUU-XSJFzmPpiKAiEAv2MDR9dsfZWYfkk3MQwRyqIgDKUFr_NbDOcKkOmIv1poYXV0aERhdGFYpEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRQAAAAEBAgMEBQYHCAECAwQFBgcIACDvKUZkwRaShwIkfrPNHHgFbXbG78GNfHZT1y9FNNWwkqUBAgMmIAEhWCC2T8LO1U5gt6dWYinNf0X_imOxyPtSIIqq3-tH0IUB8iJYIC2o7XHv3zDWr2vykXxZWMPybcnXWcAS5oWHDkZmSwqN","transports":["usb"]},"clientExtensionResults":{}}`,
			UseAAGUIDMapping:      true,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `"token"`,
		},
		{
			Name:                  "malformed api key",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:                "malformed",
			UserId:                "Lorem",
			CredName:              "cred-b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o",
			RequestBody:           `{"type":"public-key","id":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","rawId":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMnYxUEVsV2ljTGY4NGt2NFdyRURCSXJpSnF6SDJvQVhQejFWVjN0Nm9PUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgOtouIIha-G3rnDJvlVdHcNkFPC99rPWcsEQPlwwm_ukCIQD1W_2RutWFdBm6ipujAo_NjqEZa9iIde9eiWmD099AlWhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIG9CSfEJQAjm2qcSmcRniUoVqkdryU09-ZmDhCeIrivqpQECAyYgASFYIIQD9mTg5b-8jeUm4WMTjiPUnBJU0ybAjrcB2yuPVPaLIlgggf9CClQmZRnc88XPeJzqXpyw2eBOFbmNvEUFIe_-6w4","transports":["internal"]},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: `"The api key is invalid"`,
		},
		{
			Name:                  "wrong api key",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:                "bXta7uDpBt6nBn4j2sX7vm1KGqp7ma9GXPx835IiEdnJxWu_HA-rCdmdTk7I9oYQnYo4MebHkQ3khSosXJ6y5A==",
			UserId:                "Lorem",
			CredName:              "cred-b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o",
			RequestBody:           `{"type":"public-key","id":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","rawId":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMnYxUEVsV2ljTGY4NGt2NFdyRURCSXJpSnF6SDJvQVhQejFWVjN0Nm9PUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgOtouIIha-G3rnDJvlVdHcNkFPC99rPWcsEQPlwwm_ukCIQD1W_2RutWFdBm6ipujAo_NjqEZa9iIde9eiWmD099AlWhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIG9CSfEJQAjm2qcSmcRniUoVqkdryU09-ZmDhCeIrivqpQECAyYgASFYIIQD9mTg5b-8jeUm4WMTjiPUnBJU0ybAjrcB2yuPVPaLIlgggf9CClQmZRnc88XPeJzqXpyw2eBOFbmNvEUFIe_-6w4","transports":["internal"]},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: `"The api key is invalid"`,
		},
		{
			Name:                  "missing api key",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			SkipApiKey:            true,
			UserId:                "Lorem",
			CredName:              "cred-b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o",
			RequestBody:           `{"type":"public-key","id":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","rawId":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMnYxUEVsV2ljTGY4NGt2NFdyRURCSXJpSnF6SDJvQVhQejFWVjN0Nm9PUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgOtouIIha-G3rnDJvlVdHcNkFPC99rPWcsEQPlwwm_ukCIQD1W_2RutWFdBm6ipujAo_NjqEZa9iIde9eiWmD099AlWhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIG9CSfEJQAjm2qcSmcRniUoVqkdryU09-ZmDhCeIrivqpQECAyYgASFYIIQD9mTg5b-8jeUm4WMTjiPUnBJU0ybAjrcB2yuPVPaLIlgggf9CClQmZRnc88XPeJzqXpyw2eBOFbmNvEUFIe_-6w4","transports":["internal"]},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: `"The api key is invalid"`,
		},
		{
			Name:                  "malformed tenant",
			TenantId:              "malformed",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			UserId:                "Lorem",
			CredName:              "cred-b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o",
			RequestBody:           `{"type":"public-key","id":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","rawId":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMnYxUEVsV2ljTGY4NGt2NFdyRURCSXJpSnF6SDJvQVhQejFWVjN0Nm9PUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgOtouIIha-G3rnDJvlVdHcNkFPC99rPWcsEQPlwwm_ukCIQD1W_2RutWFdBm6ipujAo_NjqEZa9iIde9eiWmD099AlWhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIG9CSfEJQAjm2qcSmcRniUoVqkdryU09-ZmDhCeIrivqpQECAyYgASFYIIQD9mTg5b-8jeUm4WMTjiPUnBJU0ybAjrcB2yuPVPaLIlgggf9CClQmZRnc88XPeJzqXpyw2eBOFbmNvEUFIe_-6w4","transports":["internal"]},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: `"tenant_id must be a valid uuid4"`,
		},
		{
			Name:                  "unknown tenant",
			TenantId:              "00000000-0000-0000-0000-000000000000",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			UserId:                "Lorem",
			CredName:              "cred-b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o",
			RequestBody:           `{"type":"public-key","id":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","rawId":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMnYxUEVsV2ljTGY4NGt2NFdyRURCSXJpSnF6SDJvQVhQejFWVjN0Nm9PUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgOtouIIha-G3rnDJvlVdHcNkFPC99rPWcsEQPlwwm_ukCIQD1W_2RutWFdBm6ipujAo_NjqEZa9iIde9eiWmD099AlWhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIG9CSfEJQAjm2qcSmcRniUoVqkdryU09-ZmDhCeIrivqpQECAyYgASFYIIQD9mTg5b-8jeUm4WMTjiPUnBJU0ybAjrcB2yuPVPaLIlgggf9CClQmZRnc88XPeJzqXpyw2eBOFbmNvEUFIe_-6w4","transports":["internal"]},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: `"tenant not found"`,
		},
		{
			Name:                  "expired registration request",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"_z-CcHsvOffFBgOFVStr4rvRg9UWmdXIS6ay8Gtu97g","rawId":"_z-CcHsvOffFBgOFVStr4rvRg9UWmdXIS6ay8Gtu97g","authenticatorAttachment":"cross-platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiRDdScXRaTVhONDhsazVTN2haUGFiUVJrNTZudzNkeWFSNWhxaDRTbDQ2VSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgYtyvs2Wd9_dH522_Qjynemk6bNZYZCeV8-SmEf8cCD8CIHpKIuP6PyfDG0EyhYzjXZVRJpzS9UcKMGzt0HhinW1HY3g1Y4FZAdgwggHUMIIBeqADAgECAgEBMAoGCCqGSM49BAMCMGAxCzAJBgNVBAYTAlVTMREwDwYDVQQKDAhDaHJvbWl1bTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEaMBgGA1UEAwwRQmF0Y2ggQ2VydGlmaWNhdGUwHhcNMTcwNzE0MDI0MDAwWhcNNDQwNTMwMTIxNTU1WjBgMQswCQYDVQQGEwJVUzERMA8GA1UECgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjWF-ZclQjmS8xWc6yCpnmdo8FEZoLCWMRj__31jf0vo-bDeLU9eVxKTf-0GZ7deGLyOrrwIDtLiRG6BWmZThAaMlMCMwDAYDVR0TAQH_BAIwADATBgsrBgEEAYLlHAIBAQQEAwIFIDAKBggqhkjOPQQDAgNIADBFAiAdS_eryqvNTJUZefLA7ROApbRRoFWhTMMdeyqOuaVEwQIhANxdTGF0hhmKp-1qJtOx4bJ_jqTY3-IgYAecVcjH1DVLaGF1dGhEYXRhWKRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAAABAQIDBAUGBwgBAgMEBQYHCAAg_z-CcHsvOffFBgOFVStr4rvRg9UWmdXIS6ay8Gtu97ilAQIDJiABIVggsKAEIjWe5HmX75vyyL_rZO01oeypMur48b11Un0NIvciWCCLJ4hDtnq1kD7IFdWBqwA4wj0L3oQ2Eq1x6TNPwUJ_Dg","transports":["usb"]},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "Session has Expired",
		},
		{
			Name:                  "session challenge mismatch",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396f",
			ApiKey:                "bXta7uDpBt6nBn4j2sX7vm1KGqp7ma9GXPx835IiEdnJxWu_HA-rCdmdTk7I9oYQnYo4MebHkQ3khSosXJ6y5A==",
			RequestBody:           `{"type":"public-key","id":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","rawId":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMnYxUEVsV2ljTGY4NGt2NFdyRURCSXJpSnF6SDJvQVhQejFWVjN0Nm9PUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgOtouIIha-G3rnDJvlVdHcNkFPC99rPWcsEQPlwwm_ukCIQD1W_2RutWFdBm6ipujAo_NjqEZa9iIde9eiWmD099AlWhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIG9CSfEJQAjm2qcSmcRniUoVqkdryU09-ZmDhCeIrivqpQECAyYgASFYIIQD9mTg5b-8jeUm4WMTjiPUnBJU0ybAjrcB2yuPVPaLIlgggf9CClQmZRnc88XPeJzqXpyw2eBOFbmNvEUFIe_-6w4","transports":["internal"]},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: `"received challenge does not match with any stored one"`,
		},
		{
			Name:                  "malformed request body",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396f",
			ApiKey:                "bXta7uDpBt6nBn4j2sX7vm1KGqp7ma9GXPx835IiEdnJxWu_HA-rCdmdTk7I9oYQnYo4MebHkQ3khSosXJ6y5A==",
			RequestBody:           `{ "Lorem": "Ipsum" }`,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: `"unable to parse credential creation response"`,
		},
		{
			Name:                  "missing request body",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396f",
			ApiKey:                "bXta7uDpBt6nBn4j2sX7vm1KGqp7ma9GXPx835IiEdnJxWu_HA-rCdmdTk7I9oYQnYo4MebHkQ3khSosXJ6y5A==",
			OmitRequestBody:       true,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: `"unable to parse credential creation response"`,
		},
		{
			Name:                  "broken db",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","rawId":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMnYxUEVsV2ljTGY4NGt2NFdyRURCSXJpSnF6SDJvQVhQejFWVjN0Nm9PUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgOtouIIha-G3rnDJvlVdHcNkFPC99rPWcsEQPlwwm_ukCIQD1W_2RutWFdBm6ipujAo_NjqEZa9iIde9eiWmD099AlWhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIG9CSfEJQAjm2qcSmcRniUoVqkdryU09-ZmDhCeIrivqpQECAyYgASFYIIQD9mTg5b-8jeUm4WMTjiPUnBJU0ybAjrcB2yuPVPaLIlgggf9CClQmZRnc88XPeJzqXpyw2eBOFbmNvEUFIe_-6w4","transports":["internal"]},"clientExtensionResults":{}}`,
			SimulateBrokenDB:      true,
			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: `"Internal Server Error"`,
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadMultipleFixtures([]string{
				"../../test/fixtures/common",
				"../../test/fixtures/main_router/registration",
			})
			s.Require().NoError(err)

			var metadata mapper.AuthenticatorMetadata
			if currentTest.UseAAGUIDMapping {
				filePath := helper.ToPointer("")

				metadata = mapper.LoadAuthenticatorMetadata(filePath)

				// add mfa test aaguid for mapping
				metadata["01020304-0506-0708-0102-030405060708"] = mapper.Authenticator{
					Name:      "Test Provider",
					IconLight: "",
					IconDark:  "",
				}
			}

			mainRouter := NewMainRouter(&config.Config{}, s.Storage, metadata)

			if currentTest.SimulateBrokenDB {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			var req *http.Request
			if currentTest.OmitRequestBody {
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/mfa/registration/finalize", currentTest.TenantId), nil)
			} else {
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/mfa/registration/finalize", currentTest.TenantId), strings.NewReader(currentTest.RequestBody))
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
				creds, err := s.Storage.GetWebauthnCredentialPersister(nil).GetFromUser(currentTest.UserId, uuid.FromStringOrNil(currentTest.TenantId))
				s.Require().NoError(err)

				s.Assert().Len(creds, 1)
				s.Assert().Equal(currentTest.CredName, *creds[0].Name)
			}
		})
	}
}

func (s *mainRouterSuite) TestMainRouter_Mfa_Login_Init() {
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
			Name:                  "success",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           request.InitMfaLoginDto{UserId: "test-passkey"},
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `"publicKey":{"challenge":`,
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
			ExpectedStatusMessage: "user_id is a required field",
		},
		{
			Name:                  "missing request body",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			OmitRequestBody:       true,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "user_id is a required field",
		},
		{
			Name:                  "missing api key",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			RequestBody:           request.InitMfaLoginDto{UserId: "test-passkey"},
			SkipApiKey:            true,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "The api key is invalid",
		},
		{
			Name:                  "unknown user",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "4Yx3hvHKiJgqq3BRsmY-5zDzS52GSKcQpWumEl5aF-E",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           request.InitMfaLoginDto{UserId: "4Yx3hvHKiJgqq3BRsmY-5zDzS52GSKcQpWumEl5aF-E"},
			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "user not found",
		},
		{
			Name:                  "malformed tenant",
			TenantId:              "malformed",
			UserId:                "test-passkey",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           request.InitMfaLoginDto{UserId: "test-passkey"},
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:                  "missing tenant",
			UserId:                "test-passkey",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           request.InitMfaLoginDto{UserId: "test-passkey"},
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:                  "broken db",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           request.InitMfaLoginDto{UserId: "test-passkey"},
			SimulateBrokenDB:      true,
			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadMultipleFixtures([]string{
				"../../test/fixtures/common",
				"../../test/fixtures/main_router/login",
			})
			s.Require().NoError(err)

			mainRouter := NewMainRouter(&config.Config{}, s.Storage, nil)

			if currentTest.SimulateBrokenDB {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			var req *http.Request
			if currentTest.OmitRequestBody {
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/mfa/login/initialize", currentTest.TenantId), nil)
			} else {
				body, err := json.Marshal(currentTest.RequestBody)
				s.Require().NoError(err)

				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/mfa/login/initialize", currentTest.TenantId), bytes.NewReader(body))
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

func (s *mainRouterSuite) TestMainRouter_MFA_Login_Finish() {
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
			UserId:                "test-mfa",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"x_ofcjYOjqIIfJWBTlWbk62Bi37v-myfpr1Dhrs0-VQ","rawId":"x_ofcjYOjqIIfJWBTlWbk62Bi37v-myfpr1Dhrs0-VQ","authenticatorAttachment":"cross-platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVNFZjc3X2RaYUNfM1lJSzZ0bWN6ME9NZXZDMWR3bzVNdXo1VWZfd0pNQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg","signature":"MEUCIF7rXAv3VxIalxvMp7z55dBU5qr16hd6A_PJTjuhJ6jhAiEAnsUYUYrNcTpAT98nHmjVjyn3sH9vKJUUl2Y3bJazE1w","userHandle":"bWZhLXRlc3Q"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `{"token":"`,
		},
		{
			Name:                  "wrong tenant",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396f",
			UserId:                "test-mfa",
			ApiKey:                "bXta7uDpBt6nBn4j2sX7vm1KGqp7ma9GXPx835IiEdnJxWu_HA-rCdmdTk7I9oYQnYo4MebHkQ3khSosXJ6y5A==",
			RequestBody:           `{"type":"public-key","id":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","rawId":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoieFVpRmNLdlY3V1RQRW1FdWdTVERkWFpkcjc2RnBabC0ycVpDczBodmFodyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCICR40uXfNpSwlTIxuNBWRvRU8UTMFJcsUi9WCNzDhKqrAiEA87nlHkGPNYVoFvDe3NeODAj_EQ7auL00G8kmYjvq62U","userHandle":"YTFCMmMzRDQ"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "received challenge does not match with any stored one",
		},
		{
			Name:                  "tenant not found",
			TenantId:              "00000000-0000-0000-0000-000000000000",
			UserId:                "test-mfa",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","rawId":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoieFVpRmNLdlY3V1RQRW1FdWdTVERkWFpkcjc2RnBabC0ycVpDczBodmFodyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCICR40uXfNpSwlTIxuNBWRvRU8UTMFJcsUi9WCNzDhKqrAiEA87nlHkGPNYVoFvDe3NeODAj_EQ7auL00G8kmYjvq62U","userHandle":"YTFCMmMzRDQ"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:                  "malformed tenant",
			TenantId:              "malformed",
			UserId:                "test-mfa",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","rawId":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoieFVpRmNLdlY3V1RQRW1FdWdTVERkWFpkcjc2RnBabC0ycVpDczBodmFodyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCICR40uXfNpSwlTIxuNBWRvRU8UTMFJcsUi9WCNzDhKqrAiEA87nlHkGPNYVoFvDe3NeODAj_EQ7auL00G8kmYjvq62U","userHandle":"YTFCMmMzRDQ"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:                  "missing api key",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-mfa",
			RequestBody:           `{"type":"public-key","id":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","rawId":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoieFVpRmNLdlY3V1RQRW1FdWdTVERkWFpkcjc2RnBabC0ycVpDczBodmFodyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCICR40uXfNpSwlTIxuNBWRvRU8UTMFJcsUi9WCNzDhKqrAiEA87nlHkGPNYVoFvDe3NeODAj_EQ7auL00G8kmYjvq62U","userHandle":"YTFCMmMzRDQ"},"clientExtensionResults":{}}`,
			SkipApiKey:            true,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "The api key is invalid",
		},
		{
			Name:                  "malformed api key",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-mfa",
			ApiKey:                "malformed",
			RequestBody:           `{"type":"public-key","id":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","rawId":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoieFVpRmNLdlY3V1RQRW1FdWdTVERkWFpkcjc2RnBabC0ycVpDczBodmFodyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCICR40uXfNpSwlTIxuNBWRvRU8UTMFJcsUi9WCNzDhKqrAiEA87nlHkGPNYVoFvDe3NeODAj_EQ7auL00G8kmYjvq62U","userHandle":"YTFCMmMzRDQ"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "The api key is invalid",
		},
		{
			Name:                  "malformed user handle should be ignored",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-mfa",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"x_ofcjYOjqIIfJWBTlWbk62Bi37v-myfpr1Dhrs0-VQ","rawId":"x_ofcjYOjqIIfJWBTlWbk62Bi37v-myfpr1Dhrs0-VQ","authenticatorAttachment":"cross-platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVNFZjc3X2RaYUNfM1lJSzZ0bWN6ME9NZXZDMWR3bzVNdXo1VWZfd0pNQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg","signature":"MEUCIF7rXAv3VxIalxvMp7z55dBU5qr16hd6A_PJTjuhJ6jhAiEAnsUYUYrNcTpAT98nHmjVjyn3sH9vKJUUl2Y3bJazE1w","userHandle":"bWZhLXRlc3QtMgs"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `{"token":"`,
		},
		{
			Name:                  "wrong credential",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-mfa",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"TaCJSxWWK3UI7UovgNJHfWXDPQMm0lo6shGO6iaLGNo","rawId":"TaCJSxWWK3UI7UovgNJHfWXDPQMm0lo6shGO6iaLGNo","authenticatorAttachment":"cross-platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidEZzbGxaNTZGdUJheUxqeTJmYy1NM0Q3MGt4QU9zY3RVenVwdjk0MldrSSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg","signature":"MEYCIQCRYwDVmkcrpgH7idU35qiJH9XFs5zi9PFQcunCYe7YvwIhAK3nsXNGAyf2G1kBMJGiOaqQbyiSTDlD2itE0euh_jnJ","userHandle":"bWZhLXRlc3Q"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "Unable to find the credential for the returned credential ID",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadMultipleFixtures([]string{
				"../../test/fixtures/common",
				"../../test/fixtures/main_router/login",
			})
			s.Require().NoError(err)

			mainRouter := NewMainRouter(&config.Config{}, s.Storage, nil)

			if currentTest.SimulateBrokenDB {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			var req *http.Request
			if currentTest.OmitRequestBody {
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/mfa/login/finalize", currentTest.TenantId), nil)
			} else {
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/mfa/login/finalize", currentTest.TenantId), strings.NewReader(currentTest.RequestBody))
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
