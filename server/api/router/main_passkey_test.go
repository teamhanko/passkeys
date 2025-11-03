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

func (s *mainRouterSuite) TestMainRouter_Registration_Init() {
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
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/registration/initialize", currentTest.TenantId), nil)
			} else {
				body, err := json.Marshal(currentTest.RequestBody)
				s.Require().NoError(err)

				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/registration/initialize", currentTest.TenantId), bytes.NewReader(body))
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
				s.Equal(protocol.ResidentKeyRequirementRequired, creationOptions.Response.AuthenticatorSelection.ResidentKey)
				s.Equal(protocol.VerificationPreferred, creationOptions.Response.AuthenticatorSelection.UserVerification)
				s.True(*creationOptions.Response.AuthenticatorSelection.RequireResidentKey)
			} else {
				s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)
			}
		})
	}

}

func (s *mainRouterSuite) TestMainRouter_Registration_Finalize() {
	s.SkipOnShort()

	tests := []struct {
		Name        string
		TenantId    string
		UserId      string
		CredName    string
		RequestBody string

		OmitRequestBody  bool
		SimulateBrokenDB bool
		UseAAGUIDMapping bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:                  "success without mapping",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			CredName:              "cred-Nx1ClZkkM2ahHzFrx75xRSHaVmJVeHfYJG96ebzU_w8",
			RequestBody:           `{"type":"public-key","id":"Nx1ClZkkM2ahHzFrx75xRSHaVmJVeHfYJG96ebzU_w8","rawId":"Nx1ClZkkM2ahHzFrx75xRSHaVmJVeHfYJG96ebzU_w8","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiOVVoMlByWUh5ejBBQVAxUTdlT24xS0oxc2QtR1A5amRzSi0wTWZSSmNFRSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgWMkrzdLrZuwXfvfVg6uRtDRqIRkUTODEIKiLm-PWc-ICIQDPwr0JXMJzumKMvywSgUylC4oYS6Wn3Bkq5onnv8scqGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIDcdQpWZJDNmoR8xa8e-cUUh2lZiVXh32CRvenm81P8PpQECAyYgASFYIHrhErnErli1kll2h-IZRYOuJjUb-quJ9axUJ2OhPw8UIlgglE2cEofNgKw5Nvx6dlVokaXQLQ_CxthLHIJ-IDWaxDg","transports":["internal"]},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `"token"`,
		},
		{
			Name:                  "success with mapping",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			CredName:              "Chrome on Mac",
			RequestBody:           `{"type":"public-key","id":"Nx1ClZkkM2ahHzFrx75xRSHaVmJVeHfYJG96ebzU_w8","rawId":"Nx1ClZkkM2ahHzFrx75xRSHaVmJVeHfYJG96ebzU_w8","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiOVVoMlByWUh5ejBBQVAxUTdlT24xS0oxc2QtR1A5amRzSi0wTWZSSmNFRSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgWMkrzdLrZuwXfvfVg6uRtDRqIRkUTODEIKiLm-PWc-ICIQDPwr0JXMJzumKMvywSgUylC4oYS6Wn3Bkq5onnv8scqGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIDcdQpWZJDNmoR8xa8e-cUUh2lZiVXh32CRvenm81P8PpQECAyYgASFYIHrhErnErli1kll2h-IZRYOuJjUb-quJ9axUJ2OhPw8UIlgglE2cEofNgKw5Nvx6dlVokaXQLQ_CxthLHIJ-IDWaxDg","transports":["internal"]},"clientExtensionResults":{}}`,
			UseAAGUIDMapping:      true,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `"token"`,
		},
		{
			Name:                  "malformed tenant",
			TenantId:              "malformed",
			UserId:                "Lorem",
			CredName:              "cred-b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o",
			RequestBody:           `{"type":"public-key","id":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","rawId":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMnYxUEVsV2ljTGY4NGt2NFdyRURCSXJpSnF6SDJvQVhQejFWVjN0Nm9PUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgOtouIIha-G3rnDJvlVdHcNkFPC99rPWcsEQPlwwm_ukCIQD1W_2RutWFdBm6ipujAo_NjqEZa9iIde9eiWmD099AlWhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIG9CSfEJQAjm2qcSmcRniUoVqkdryU09-ZmDhCeIrivqpQECAyYgASFYIIQD9mTg5b-8jeUm4WMTjiPUnBJU0ybAjrcB2yuPVPaLIlgggf9CClQmZRnc88XPeJzqXpyw2eBOFbmNvEUFIe_-6w4","transports":["internal"]},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: `"tenant_id must be a valid uuid4"`,
		},
		{
			Name:                  "unknown tenant",
			TenantId:              "00000000-0000-0000-0000-000000000000",
			UserId:                "Lorem",
			CredName:              "cred-b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o",
			RequestBody:           `{"type":"public-key","id":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","rawId":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMnYxUEVsV2ljTGY4NGt2NFdyRURCSXJpSnF6SDJvQVhQejFWVjN0Nm9PUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgOtouIIha-G3rnDJvlVdHcNkFPC99rPWcsEQPlwwm_ukCIQD1W_2RutWFdBm6ipujAo_NjqEZa9iIde9eiWmD099AlWhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIG9CSfEJQAjm2qcSmcRniUoVqkdryU09-ZmDhCeIrivqpQECAyYgASFYIIQD9mTg5b-8jeUm4WMTjiPUnBJU0ybAjrcB2yuPVPaLIlgggf9CClQmZRnc88XPeJzqXpyw2eBOFbmNvEUFIe_-6w4","transports":["internal"]},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: `"tenant not found"`,
		},
		{
			Name:                  "expired registration request",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody:           `{"type":"public-key","id":"Jqujwmwsy7WxLZ6czY3DVP4COna_n2jMQa9_xVQSzfM","rawId":"Jqujwmwsy7WxLZ6czY3DVP4COna_n2jMQa9_xVQSzfM","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiM1dTUGNIQVFhXzdRdHR2M0pQZEVHRFhfcG1ISnRKNGZRNl91RERDMFFkYyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEYwRAIgO3FYNOi5bGuC38yswBmnY7ktTRYNTQg0IMzQQ1hRhmsCIGxct34SgyWtpfIUJA5tT9Sr9TU5H51b5WHitxVuPNOdaGF1dGhEYXRhWKRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAAAArc4AAjW8xgpkiwsl8fBVAwAgJqujwmwsy7WxLZ6czY3DVP4COna_n2jMQa9_xVQSzfOlAQIDJiABIVggt-w6lzMq9rD8Zzd8ec-E9t5shm0-QUOvDVqLSF46JE4iWCBK8XoTbSF50pI-YZ1rzCdtpTsmp4TE_RwhEQu0M19yxw","transports":["internal"]},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "Session has Expired",
		},
		{
			Name:                  "session challenge mismatch",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396f",
			RequestBody:           `{"type":"public-key","id":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","rawId":"b0JJ8QlACObapxKZxGeJShWqR2vJTT35mYOEJ4iuK-o","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMnYxUEVsV2ljTGY4NGt2NFdyRURCSXJpSnF6SDJvQVhQejFWVjN0Nm9PUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgOtouIIha-G3rnDJvlVdHcNkFPC99rPWcsEQPlwwm_ukCIQD1W_2RutWFdBm6ipujAo_NjqEZa9iIde9eiWmD099AlWhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIG9CSfEJQAjm2qcSmcRniUoVqkdryU09-ZmDhCeIrivqpQECAyYgASFYIIQD9mTg5b-8jeUm4WMTjiPUnBJU0ybAjrcB2yuPVPaLIlgggf9CClQmZRnc88XPeJzqXpyw2eBOFbmNvEUFIe_-6w4","transports":["internal"]},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: `"received challenge does not match with any stored one"`,
		},
		{
			Name:                  "malformed request body",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396f",
			RequestBody:           `{ "Lorem": "Ipsum" }`,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: `"unable to parse credential creation response"`,
		},
		{
			Name:                  "missing request body",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396f",
			OmitRequestBody:       true,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: `"unable to parse credential creation response"`,
		},
		{
			Name:                  "broken db",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
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

			var filePath *string
			if !currentTest.UseAAGUIDMapping {
				filePath = helper.ToPointer(".")
			}

			mainRouter := NewMainRouter(&config.Config{}, s.Storage, mapper.LoadAuthenticatorMetadata(filePath))

			if currentTest.SimulateBrokenDB {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			var req *http.Request
			if currentTest.OmitRequestBody {
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/registration/finalize", currentTest.TenantId), nil)
			} else {
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/registration/finalize", currentTest.TenantId), strings.NewReader(currentTest.RequestBody))
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

func (s *mainRouterSuite) TestMainRouter_Login_Init() {
	s.SkipOnShort()

	tests := []struct {
		Name            string
		TenantId        string
		UserId          string
		ApiKey          string
		RequestBody     interface{}
		IsDiscoverLogin bool

		SkipApiKey       bool
		SimulateBrokenDB bool
		OmitRequestBody  bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:                  "success with discovery",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			OmitRequestBody:       true,
			SkipApiKey:            true,
			IsDiscoverLogin:       true,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `"publicKey":{"challenge":`,
		},
		{
			Name:                  "success without discovery",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           request.InitLoginDto{UserId: helper.ToPointer("test-passkey")},
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `"publicKey":{"challenge":`,
		},
		{
			Name:            "perform discovery on malformed request body",
			TenantId:        "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:          "test-passkey",
			IsDiscoverLogin: true,
			ApiKey:          "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody: struct {
				Lorem string `json:"lorem"`
			}{
				Lorem: "malformed",
			},
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `"publicKey":{"challenge":`,
		},
		{
			Name:                  "perform discovery on missing request body",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			OmitRequestBody:       true,
			IsDiscoverLogin:       true,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `"publicKey":{"challenge":`,
		},
		{
			Name:                  "missing api key on non discovery",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			RequestBody:           request.InitLoginDto{UserId: helper.ToPointer("test-passkey")},
			SkipApiKey:            true,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "api key is missing",
		},
		{
			Name:                  "malformed api key on non discovery",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			ApiKey:                "malformed",
			RequestBody:           request.InitLoginDto{UserId: helper.ToPointer("test-passkey")},
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "The api key is invalid",
		},
		{
			Name:                  "unknown user",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           request.InitLoginDto{UserId: helper.ToPointer("not_found")},
			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "user not found",
		},
		{
			Name:                  "malformed tenant",
			TenantId:              "malformed",
			UserId:                "test-passkey",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           request.InitLoginDto{UserId: helper.ToPointer("test-passkey")},
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:                  "missing tenant",
			UserId:                "test-passkey",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           request.InitLoginDto{UserId: helper.ToPointer("test-passkey")},
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:                  "broken db",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           request.InitLoginDto{UserId: helper.ToPointer("a1B2c3D3")},
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
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/login/initialize", currentTest.TenantId), nil)
			} else {
				body, err := json.Marshal(currentTest.RequestBody)
				s.Require().NoError(err)

				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/login/initialize", currentTest.TenantId), bytes.NewReader(body))
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
				s.Assert().Equal(currentTest.IsDiscoverLogin, sessionData.IsDiscoverable)
			}
		})
	}
}

func (s *mainRouterSuite) TestMainRouter_Login_Finish() {
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
			Name:                  "success without discovery",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"9QEeUpkDJqEy4sa7JUe1PjpYMSO4nQQNN9X-kK0wTFQ","rawId":"9QEeUpkDJqEy4sa7JUe1PjpYMSO4nQQNN9X-kK0wTFQ","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiMEw3bTUyTmVEM0xpMXFteVhUMVp4Mk5nQ1lnNEstQTNiamQ4TzA5dmxVMCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCIQCzxd6TRox_Dx4lOPrLYpfj4umnx4aNPZ1Tg7QA4OZtWwIgMSPL_oMUENDy1I5rGSmUjNs73eDtOVTq_D6wNs4qeDE","userHandle":"dGVzdC1wYXNza2V5"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `{"token":"`,
		},
		{
			Name:                  "success with discovery",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey-discover",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"af5_nnDDP1eN3BPORT5cDfbSwfiPGy-9j85KdB3WQ6w","rawId":"af5_nnDDP1eN3BPORT5cDfbSwfiPGy-9j85KdB3WQ6w","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVWljUDNmb0dQZmFoZF9kdVlHbnVCeVNtVldhUGw5VkNOSzdCNDJpM2Z4ayIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCIF-LTHRYEHX4r9pWj39-o2NglZV8U3wGvOkmT-KH2ecjAiEA_1dYDRgiJsx7_1i9kIX8YWqzUlOzzHlz9HJgj0dGPmQ","userHandle":"dGVzdC1wYXNza2V5LWRpc2NvdmVy"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `{"token":"`,
		},
		{
			Name:                  "wrong tenant",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396f",
			UserId:                "a1B2c3D4",
			ApiKey:                "d3917w2_RXsixVaJn2QZn4BmqrRs-G_rNmTTA2Few_lxXMNzv_7aI1uJCg_mJp7h5PdstRSD5LTrvWfwEF0PNg==",
			RequestBody:           `{"type":"public-key","id":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","rawId":"AINIobIYxCyd9-4CtiRLM2T7qiR0QRyG28yg6XrgaOY","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoieFVpRmNLdlY3V1RQRW1FdWdTVERkWFpkcjc2RnBabC0ycVpDczBodmFodyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCICR40uXfNpSwlTIxuNBWRvRU8UTMFJcsUi9WCNzDhKqrAiEA87nlHkGPNYVoFvDe3NeODAj_EQ7auL00G8kmYjvq62U","userHandle":"YTFCMmMzRDQ"},"clientExtensionResults":{}}`,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "received challenge does not match with any stored one",
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
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `{"token":"`,
		},
		{
			Name:                  "success with malformed api key",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "test-passkey",
			ApiKey:                "malformed",
			RequestBody:           `{"type":"public-key","id":"9QEeUpkDJqEy4sa7JUe1PjpYMSO4nQQNN9X-kK0wTFQ","rawId":"9QEeUpkDJqEy4sa7JUe1PjpYMSO4nQQNN9X-kK0wTFQ","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiMEw3bTUyTmVEM0xpMXFteVhUMVp4Mk5nQ1lnNEstQTNiamQ4TzA5dmxVMCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCIQCzxd6TRox_Dx4lOPrLYpfj4umnx4aNPZ1Tg7QA4OZtWwIgMSPL_oMUENDy1I5rGSmUjNs73eDtOVTq_D6wNs4qeDE","userHandle":"dGVzdC1wYXNza2V5"},"clientExtensionResults":{}}`,
			SkipApiKey:            false,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: `{"token":"`,
		},
		{
			Name:                  "wrong user handle",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "a1B2c3D4",
			RequestBody:           `{"type":"public-key","id":"af5_nnDDP1eN3BPORT5cDfbSwfiPGy-9j85KdB3WQ6w","rawId":"af5_nnDDP1eN3BPORT5cDfbSwfiPGy-9j85KdB3WQ6w","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVWljUDNmb0dQZmFoZF9kdVlHbnVCeVNtVldhUGw5VkNOSzdCNDJpM2Z4ayIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCIF-LTHRYEHX4r9pWj39-o2NglZV8U3wGvOkmT-KH2ecjAiEA_1dYDRgiJsx7_1i9kIX8YWqzUlOzzHlz9HJgj0dGPmQ","userHandle":"dGVzdC13cm9uZy11c2VyLWhhbmRsZQ=="},"clientExtensionResults":{}}`,
			SkipApiKey:            true,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "failed to get user by user handle",
		},
		{
			Name:                  "wrong credential",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "a1B2c3D4",
			RequestBody:           `{"type":"public-key","id":"9QEeUpkDJqEy4sa7JUe1PjpYMSO4nQQNN9X-kK0wTFQ","rawId":"9QEeUpkDJqEy4sa7JUe1PjpYMSO4nQQNN9X-kK0wTFQ","authenticatorAttachment":"platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZGNqSmJtSDh3eHVCZ1p3QXdzeF84WFFuSFgxYlJCVjFoWHo3TDJ0UF91QSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA","signature":"MEUCIG9UopCXxa8o_Lk_-fJRgzV-6Bi8-DlTjkvAQYFpKZliAiEAgbZe4h24DHpzqKhk84LuQJmOHiXAuQz67fbo8DGJZZ8","userHandle":"dGVzdC1wYXNza2V5LWRpc2NvdmVy"},"clientExtensionResults":{}}`,
			SkipApiKey:            true,
			ExpectedStatusCode:    http.StatusUnauthorized,
			ExpectedStatusMessage: "received challenge does not match with any stored one",
		},
		{
			Name:                  "fail to use mfa credential",
			TenantId:              "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			UserId:                "mfa-test",
			RequestBody:           `{"type":"public-key","id":"x_ofcjYOjqIIfJWBTlWbk62Bi37v-myfpr1Dhrs0-VQ","rawId":"x_ofcjYOjqIIfJWBTlWbk62Bi37v-myfpr1Dhrs0-VQ","authenticatorAttachment":"cross-platform","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVNFZjc3X2RaYUNfM1lJSzZ0bWN6ME9NZXZDMWR3bzVNdXo1VWZfd0pNQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg","signature":"MEUCIF7rXAv3VxIalxvMp7z55dBU5qr16hd6A_PJTjuhJ6jhAiEAnsUYUYrNcTpAT98nHmjVjyn3sH9vKJUUl2Y3bJazE1w","userHandle":"bWZhLXRlc3Q"},"clientExtensionResults":{}}`,
			SkipApiKey:            true,
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
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/login/finalize", currentTest.TenantId), nil)
			} else {
				req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/login/finalize", currentTest.TenantId), strings.NewReader(currentTest.RequestBody))
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
