package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/api/dto/admin/request"
	"github.com/teamhanko/passkey-server/api/dto/admin/response"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/test/helper"
	"net/http"
	"net/http/httptest"
	"time"
)

func (s *adminSuite) TestAdminRouter_Tenants_Lists() {
	s.SkipOnShort()

	tests := []struct {
		Name string

		SimulateBrokenDB bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
		ExpectedTenantCount   int
	}{
		{
			Name:                "success",
			ExpectedStatusCode:  http.StatusOK,
			ExpectedTenantCount: 2,
		},
		{
			Name:                  "broken db",
			SimulateBrokenDB:      true,
			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadFixtures("../../test/fixtures/common")
			s.Require().NoError(err)

			adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)

			req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
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
				var tenants response.ListTenantResponses
				err := json.Unmarshal(rec.Body.Bytes(), &tenants)
				s.Require().NoError(err)

				s.Assert().Len(tenants, 4)
			}

		})
	}
}

func (s *adminSuite) TestAdminRouter_Tenants_Create() {
	s.SkipOnShort()

	tests := []struct {
		Name string

		RequestBody request.CreateTenantDto

		SimulateBrokenDB    bool
		OmitRequestBody     bool
		InvertExpectMessage bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name: "success",
			RequestBody: request.CreateTenantDto{
				DisplayName: "Test-Tenant",
				Config: request.CreateConfigDto{
					Cors: request.CreateCorsDto{
						AllowedOrigins:      []string{"http://localhost"},
						AllowUnsafeWildcard: helper.ToPointer(true),
					},
					Passkey: request.CreatePasskeyConfigDto{
						RelyingParty: request.CreateRelyingPartyDto{
							Id:          "localhost",
							DisplayName: "Localhost",
							Icon:        nil,
							Origins:     []string{"http://localhost"},
						},
						Timeout:                6000,
						UserVerification:       helper.ToPointer(protocol.VerificationDiscouraged),
						AttestationPreference:  helper.ToPointer(protocol.PreferDirectAttestation),
						ResidentKeyRequirement: helper.ToPointer(protocol.ResidentKeyRequirementDiscouraged),
					},
					Mfa: &request.CreateMFAConfigDto{
						Timeout:                5000,
						UserVerification:       helper.ToPointer(protocol.VerificationRequired),
						AttestationPreference:  helper.ToPointer(protocol.PreferIndirectAttestation),
						ResidentKeyRequirement: helper.ToPointer(protocol.ResidentKeyRequirementPreferred),
						Attachment:             helper.ToPointer(protocol.CrossPlatform),
					},
				},
				CreateApiKey: true,
			},

			ExpectedStatusCode:    http.StatusCreated,
			ExpectedStatusMessage: `"name":"Initial API Key"`,
		},
		{
			Name: "success with missing mfa config",
			RequestBody: request.CreateTenantDto{
				DisplayName: "Test-Tenant",
				Config: request.CreateConfigDto{
					Cors: request.CreateCorsDto{
						AllowedOrigins:      []string{"http://localhost"},
						AllowUnsafeWildcard: helper.ToPointer(true),
					},
					Passkey: request.CreatePasskeyConfigDto{
						RelyingParty: request.CreateRelyingPartyDto{
							Id:          "localhost",
							DisplayName: "Localhost",
							Icon:        nil,
							Origins:     []string{"http://localhost"},
						},
						Timeout:                6000,
						UserVerification:       helper.ToPointer(protocol.VerificationDiscouraged),
						AttestationPreference:  helper.ToPointer(protocol.PreferDirectAttestation),
						ResidentKeyRequirement: helper.ToPointer(protocol.ResidentKeyRequirementDiscouraged),
					},
				},
				CreateApiKey: true,
			},

			ExpectedStatusCode:    http.StatusCreated,
			ExpectedStatusMessage: `"name":"Initial API Key"`,
		},
		{
			Name: "success with minimal config",
			RequestBody: request.CreateTenantDto{
				DisplayName: "Test-Tenant",
				Config: request.CreateConfigDto{
					Cors: request.CreateCorsDto{
						AllowedOrigins:      []string{"http://localhost"},
						AllowUnsafeWildcard: helper.ToPointer(true),
					},
					Passkey: request.CreatePasskeyConfigDto{
						RelyingParty: request.CreateRelyingPartyDto{
							Id:          "localhost",
							DisplayName: "Localhost",
							Origins:     []string{"http://localhost"},
						},
						Timeout: 6000,
					},
				},
				CreateApiKey: true,
			},

			ExpectedStatusCode:    http.StatusCreated,
			ExpectedStatusMessage: `"name":"Initial API Key"`,
		},
		{
			Name: "success without api key",
			RequestBody: request.CreateTenantDto{
				DisplayName: "Test-Tenant",
				Config: request.CreateConfigDto{
					Cors: request.CreateCorsDto{
						AllowedOrigins:      []string{"http://localhost"},
						AllowUnsafeWildcard: helper.ToPointer(true),
					},
					Passkey: request.CreatePasskeyConfigDto{
						RelyingParty: request.CreateRelyingPartyDto{
							Id:          "localhost",
							DisplayName: "Localhost",
							Origins:     []string{"http://localhost"},
						},
						Timeout: 6000,
					},
				},
				CreateApiKey: false,
			},

			InvertExpectMessage: true,

			ExpectedStatusCode:    http.StatusCreated,
			ExpectedStatusMessage: `"name":"Initial API Key"`,
		},
		{
			Name: "missing required attributes",
			RequestBody: request.CreateTenantDto{
				DisplayName: "Test-Tenant",
				Config: request.CreateConfigDto{
					Cors: request.CreateCorsDto{
						AllowedOrigins: []string{"http://localhost"},
					},
					Passkey: request.CreatePasskeyConfigDto{
						RelyingParty: request.CreateRelyingPartyDto{
							Id:          "localhost",
							DisplayName: "Localhost",
							Origins:     []string{"http://localhost"},
						},
					},
				},
				CreateApiKey: true,
			},

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: `"details":"allow_unsafe_wildcard is a required field and timeout is a required field"`,
		},
		{
			Name:            "missing request body",
			OmitRequestBody: true,

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: `"details":"display_name is a required field and allowed_origins is a required field and allow_unsafe_wildcard is a required field and id is a required field and display_name is a required field and origins is a required field and timeout is a required field"`,
		},
		{
			Name: "broken db",
			RequestBody: request.CreateTenantDto{
				DisplayName: "Test-Tenant",
				Config: request.CreateConfigDto{
					Cors: request.CreateCorsDto{
						AllowedOrigins:      []string{"http://localhost"},
						AllowUnsafeWildcard: helper.ToPointer(true),
					},
					Passkey: request.CreatePasskeyConfigDto{
						RelyingParty: request.CreateRelyingPartyDto{
							Id:          "localhost",
							DisplayName: "Localhost",
							Icon:        nil,
							Origins:     []string{"http://localhost"},
						},
						Timeout:                6000,
						UserVerification:       helper.ToPointer(protocol.VerificationDiscouraged),
						AttestationPreference:  helper.ToPointer(protocol.PreferDirectAttestation),
						ResidentKeyRequirement: helper.ToPointer(protocol.ResidentKeyRequirementDiscouraged),
					},
					Mfa: &request.CreateMFAConfigDto{
						Timeout:                5000,
						UserVerification:       helper.ToPointer(protocol.VerificationRequired),
						AttestationPreference:  helper.ToPointer(protocol.PreferIndirectAttestation),
						ResidentKeyRequirement: helper.ToPointer(protocol.ResidentKeyRequirementPreferred),
						Attachment:             helper.ToPointer(protocol.CrossPlatform),
					},
				},
				CreateApiKey: true,
			},

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
			if !currentTest.OmitRequestBody {
				body, err := json.Marshal(currentTest.RequestBody)
				s.Require().NoError(err)

				req = httptest.NewRequest(http.MethodPost, "/tenants", bytes.NewReader(body))
			} else {
				req = httptest.NewRequest(http.MethodPost, "/tenants", nil)
			}
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDB {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			adminRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)

			if currentTest.InvertExpectMessage {
				s.Assert().NotContains(rec.Body.String(), currentTest.ExpectedStatusMessage)
			} else {
				s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)
			}

		})
	}
}

func (s *adminSuite) TestAdminRouter_Tenants_Get() {
	s.SkipOnShort()

	tests := []struct {
		Name     string
		TenantID string

		SimulateBrokenDB bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:     "success",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			ExpectedStatusCode: http.StatusOK,
		},
		{
			Name:     "unknown tenant",
			TenantID: "00000000-0000-0000-0000-000000000000",

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:     "malformed tenant id",
			TenantID: "malformed",

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant must be valid uuid4",
		},
		{
			Name:     "missing tenant id",
			TenantID: "/",

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant must be valid uuid4",
		},
		{
			Name:     "broken db",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

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

			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/tenants/%s", currentTest.TenantID), nil)
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDB {
				err = s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			adminRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)

			if rec.Code == http.StatusOK {
				var tenant response.GetTenantResponse
				err = json.Unmarshal(rec.Body.Bytes(), &tenant)
				s.Require().NoError(err)

				s.Assert().NotEmpty(tenant)
				s.Assert().Equal(currentTest.TenantID, tenant.Id.String())
				s.Assert().Equal("Success Tenant", tenant.DisplayName)
				s.Assert().NotEmpty(tenant.Config)
			}
		})
	}
}

func (s *adminSuite) TestAdminRouter_Tenants_Update() {
	s.SkipOnShort()

	tests := []struct {
		Name        string
		TenantID    string
		DisplayName string
		RequestBody interface{}

		OmitRequestBody  bool
		SimulateBrokenDB bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:        "success",
			TenantID:    "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			DisplayName: "Lorem",
			RequestBody: request.UpdateTenantDto{DisplayName: "Lorem"},

			ExpectedStatusCode: http.StatusNoContent,
		},
		{
			Name:        "tenant not found",
			TenantID:    "00000000-0000-0000-0000-000000000000",
			DisplayName: "Lorem",
			RequestBody: request.UpdateTenantDto{DisplayName: "Lorem"},

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:        "malformed tenant id",
			TenantID:    "malformed",
			DisplayName: "Lorem",
			RequestBody: request.UpdateTenantDto{DisplayName: "Lorem"},

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:        "missing request body",
			TenantID:    "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			DisplayName: "Lorem",

			OmitRequestBody: true,

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "display_name is a required field",
		},
		{
			Name:        "malformed request body",
			TenantID:    "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			DisplayName: "Lorem",
			RequestBody: struct {
				Lorem string `json:"lorem"`
			}{
				Lorem: "Ipsum",
			},

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "display_name is a required field",
		},
		{
			Name:        "malformed display name",
			TenantID:    "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			DisplayName: "Lorem",
			RequestBody: request.UpdateTenantDto{DisplayName: ""},

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "display_name is a required field",
		},
		{
			Name:        "broken db",
			TenantID:    "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			DisplayName: "Lorem",
			RequestBody: request.UpdateTenantDto{DisplayName: "Lorem"},

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
				req = httptest.NewRequest(http.MethodPut, fmt.Sprintf("/tenants/%s", currentTest.TenantID), nil)
			} else {
				body, err := json.Marshal(currentTest.RequestBody)
				s.Require().NoError(err)

				req = httptest.NewRequest(http.MethodPut, fmt.Sprintf("/tenants/%s", currentTest.TenantID), bytes.NewReader(body))
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

			if rec.Code == http.StatusOK {
				tenant, err := s.Storage.GetTenantPersister(nil).Get(uuid.FromStringOrNil(currentTest.TenantID))
				s.Require().NoError(err)
				s.Assert().Equal(currentTest.DisplayName, tenant.DisplayName)
			}
		})
	}
}

func (s *adminSuite) TestAdminRouter_Tenants_Remove() {
	s.SkipOnShort()

	tests := []struct {
		Name     string
		TenantID string

		SimulateBrokenDB bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:     "success",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			ExpectedStatusCode: http.StatusNoContent,
		},
		{
			Name:     "tenant not found",
			TenantID: "00000000-0000-0000-0000-000000000000",

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:     "malformed tenant id",
			TenantID: "malformed",

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:     "broken db",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			SimulateBrokenDB: true,

			ExpectedStatusCode:    http.StatusInternalServerError,
			ExpectedStatusMessage: "Internal Server Error",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadFixtures("../../test/fixtures/common")
			s.Require().NoError(err)

			beforeDelete, err := s.Storage.GetTenantPersister(nil).List()
			s.Require().NoError(err)

			adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)

			req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/tenants/%s", currentTest.TenantID), nil)
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDB {
				err = s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			adminRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)

			if rec.Code == http.StatusOK {
				afterDelete, err := s.Storage.GetTenantPersister(nil).List()
				s.Require().NoError(err)

				s.Assert().Less(afterDelete, beforeDelete)

				tenant, err := s.Storage.GetTenantPersister(nil).Get(uuid.FromStringOrNil(currentTest.TenantID))
				s.Require().NoError(err)

				s.Assert().Empty(tenant)
			}
		})
	}
}

func (s *adminSuite) TestAdminRouter_Tenants_UpdateConfig() {
	s.SkipOnShort()

	tests := []struct {
		Name        string
		TenantID    string
		RequestBody interface{}

		OmitRequestBody  bool
		SkipConfigCheck  bool
		SimulateBrokenDB bool

		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:     "success",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: request.UpdateConfigDto{
				CreateConfigDto: request.CreateConfigDto{
					Cors: request.CreateCorsDto{
						AllowedOrigins:      []string{"http://localhost"},
						AllowUnsafeWildcard: helper.ToPointer(true),
					},
					Passkey: request.CreatePasskeyConfigDto{
						RelyingParty: request.CreateRelyingPartyDto{
							Id:          "localhost",
							DisplayName: "Localhost",
							Icon:        helper.ToPointer("http://localhost/img.png"),
							Origins:     []string{"http://localhost"},
						},
						Timeout:                1234,
						UserVerification:       helper.ToPointer(protocol.VerificationDiscouraged),
						Attachment:             helper.ToPointer(protocol.Platform),
						AttestationPreference:  helper.ToPointer(protocol.PreferDirectAttestation),
						ResidentKeyRequirement: helper.ToPointer(protocol.ResidentKeyRequirementDiscouraged),
					},
					Mfa: helper.ToPointer(request.CreateMFAConfigDto{
						Timeout:                1234,
						UserVerification:       helper.ToPointer(protocol.VerificationPreferred),
						Attachment:             helper.ToPointer(protocol.Platform),
						AttestationPreference:  helper.ToPointer(protocol.PreferIndirectAttestation),
						ResidentKeyRequirement: helper.ToPointer(protocol.ResidentKeyRequirementPreferred),
					}),
				},
			},

			ExpectedStatusCode: http.StatusNoContent,
		},
		{
			Name:     "success with minimal config",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: request.UpdateConfigDto{
				CreateConfigDto: request.CreateConfigDto{
					Cors: request.CreateCorsDto{
						AllowedOrigins:      []string{"http://localhost"},
						AllowUnsafeWildcard: helper.ToPointer(true),
					},
					Passkey: request.CreatePasskeyConfigDto{
						RelyingParty: request.CreateRelyingPartyDto{
							Id:          "localhost",
							DisplayName: "Localhost",
							Origins:     []string{"http://localhost"},
						},
						Timeout: 1234,
					},
				},
			},

			ExpectedStatusCode: http.StatusNoContent,
		},
		{
			Name:     "tenant not found",
			TenantID: "00000000-0000-0000-0000-000000000000",
			RequestBody: request.UpdateConfigDto{
				CreateConfigDto: request.CreateConfigDto{
					Cors: request.CreateCorsDto{
						AllowedOrigins:      []string{"http://localhost"},
						AllowUnsafeWildcard: helper.ToPointer(true),
					},
					Passkey: request.CreatePasskeyConfigDto{
						RelyingParty: request.CreateRelyingPartyDto{
							Id:          "localhost",
							DisplayName: "Localhost",
							Icon:        helper.ToPointer("http://localhost/img.png"),
							Origins:     []string{"http://localhost"},
						},
						Timeout:                1234,
						UserVerification:       helper.ToPointer(protocol.VerificationDiscouraged),
						Attachment:             helper.ToPointer(protocol.Platform),
						AttestationPreference:  helper.ToPointer(protocol.PreferDirectAttestation),
						ResidentKeyRequirement: helper.ToPointer(protocol.ResidentKeyRequirementDiscouraged),
					},
					Mfa: helper.ToPointer(request.CreateMFAConfigDto{
						Timeout:                1234,
						UserVerification:       helper.ToPointer(protocol.VerificationPreferred),
						Attachment:             helper.ToPointer(protocol.Platform),
						AttestationPreference:  helper.ToPointer(protocol.PreferIndirectAttestation),
						ResidentKeyRequirement: helper.ToPointer(protocol.ResidentKeyRequirementPreferred),
					}),
				},
			},

			SkipConfigCheck: true,

			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:     "malformed tenant",
			TenantID: "malformed",
			RequestBody: request.UpdateConfigDto{
				CreateConfigDto: request.CreateConfigDto{
					Cors: request.CreateCorsDto{
						AllowedOrigins:      []string{"http://localhost"},
						AllowUnsafeWildcard: helper.ToPointer(true),
					},
					Passkey: request.CreatePasskeyConfigDto{
						RelyingParty: request.CreateRelyingPartyDto{
							Id:          "localhost",
							DisplayName: "Localhost",
							Icon:        helper.ToPointer("http://localhost/img.png"),
							Origins:     []string{"http://localhost"},
						},
						Timeout:                1234,
						UserVerification:       helper.ToPointer(protocol.VerificationDiscouraged),
						Attachment:             helper.ToPointer(protocol.Platform),
						AttestationPreference:  helper.ToPointer(protocol.PreferDirectAttestation),
						ResidentKeyRequirement: helper.ToPointer(protocol.ResidentKeyRequirementDiscouraged),
					},
					Mfa: helper.ToPointer(request.CreateMFAConfigDto{
						Timeout:                1234,
						UserVerification:       helper.ToPointer(protocol.VerificationPreferred),
						Attachment:             helper.ToPointer(protocol.Platform),
						AttestationPreference:  helper.ToPointer(protocol.PreferIndirectAttestation),
						ResidentKeyRequirement: helper.ToPointer(protocol.ResidentKeyRequirementPreferred),
					}),
				},
			},

			SkipConfigCheck: true,

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:     "malformed attribute",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: request.UpdateConfigDto{
				CreateConfigDto: request.CreateConfigDto{
					Cors: request.CreateCorsDto{
						AllowedOrigins:      []string{"http://localhost"},
						AllowUnsafeWildcard: helper.ToPointer(true),
					},
					Passkey: request.CreatePasskeyConfigDto{
						RelyingParty: request.CreateRelyingPartyDto{
							Id:          "localhost",
							DisplayName: "Localhost",
							Icon:        helper.ToPointer("lorem"),
							Origins:     []string{"http://localhost"},
						},
						Timeout: 1234,
					},
				},
			},

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "icon must be a valid URL",
		},
		{
			Name:     "malformed request body",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: struct {
				Lorem string `json:"lorem"`
			}{
				Lorem: "Ipsum",
			},

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "allowed_origins is a required field and allow_unsafe_wildcard is a required field and id is a required field and display_name is a required field and origins is a required field and timeout is a required field",
		},
		{
			Name:            "missing request body",
			TenantID:        "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			OmitRequestBody: true,

			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "allowed_origins is a required field and allow_unsafe_wildcard is a required field and id is a required field and display_name is a required field and origins is a required field and timeout is a required field",
		},
		{
			Name:     "broken db",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: request.UpdateConfigDto{
				CreateConfigDto: request.CreateConfigDto{
					Cors: request.CreateCorsDto{
						AllowedOrigins:      []string{"http://localhost"},
						AllowUnsafeWildcard: helper.ToPointer(true),
					},
					Passkey: request.CreatePasskeyConfigDto{
						RelyingParty: request.CreateRelyingPartyDto{
							Id:          "localhost",
							DisplayName: "Localhost",
							Origins:     []string{"http://localhost"},
						},
						Timeout: 1234,
					},
				},
			},

			SkipConfigCheck:  true,
			SimulateBrokenDB: true,

			ExpectedStatusCode: http.StatusNoContent,
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			err := s.LoadFixtures("../../test/fixtures/common")
			s.Require().NoError(err)

			var oldConfig models.Config
			if !currentTest.SkipConfigCheck {
				oldTenant, err := s.Storage.GetTenantPersister(nil).Get(uuid.FromStringOrNil(currentTest.TenantID))
				s.Require().NoError(err)

				oldConfig = oldTenant.Config

			}

			adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)

			var req *http.Request
			if currentTest.OmitRequestBody {
				req = httptest.NewRequest(http.MethodPut, fmt.Sprintf("/tenants/%s/config", currentTest.TenantID), nil)
			} else {
				body, err := json.Marshal(currentTest.RequestBody)
				s.Require().NoError(err)

				req = httptest.NewRequest(http.MethodPut, fmt.Sprintf("/tenants/%s/config", currentTest.TenantID), bytes.NewReader(body))
			}

			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			adminRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)

			if !currentTest.SkipConfigCheck && rec.Code == http.StatusOK {
				updatedTenant, err := s.Storage.GetTenantPersister(nil).Get(uuid.FromStringOrNil(currentTest.TenantID))
				s.Require().NoError(err)

				updatedConfig := updatedTenant.Config

				s.Assert().Equal(oldConfig.ID, updatedConfig.ID)
				s.Assert().NotEqual(oldConfig.WebauthnConfig.Timeout, updatedConfig.WebauthnConfig.Timeout)
			}
		})
	}
}

func (s *adminSuite) TestAdminRouter_Tenants_AuditLogs() {
	s.SkipOnShort()

	tests := []struct {
		Name        string
		TenantID    string
		RequestBody interface{}

		OmitRequestBody  bool
		SimulateBrokenDB bool

		ExpectedLogCount      int
		ExpectedStatusCode    int
		ExpectedStatusMessage string
	}{
		{
			Name:     "success",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: request.ListAuditLogDto{
				Page:         1,
				PerPage:      2,
				StartTime:    helper.ToPointer(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
				EndTime:      helper.ToPointer(time.Now()),
				Types:        []string{"webauthn_transaction_init_succeeded"},
				UserId:       "test-passkey",
				IP:           "192.168.65.1",
				SearchString: "192.168.",
			},

			ExpectedLogCount:      1,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: "[",
		},
		{
			Name:        "success with minimal request body",
			TenantID:    "6eb4710c-72df-4941-984d-f2cf3dbe396e",
			RequestBody: request.ListAuditLogDto{},

			ExpectedLogCount:      2,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: "[",
		},
		{
			Name:     "success with no request body",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			OmitRequestBody: true,

			ExpectedLogCount:      2,
			ExpectedStatusCode:    http.StatusOK,
			ExpectedStatusMessage: "[",
		},
		{
			Name:     "unknown tenant",
			TenantID: "00000000-0000-0000-0000-000000000000",

			OmitRequestBody: true,

			ExpectedLogCount:      0,
			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedStatusMessage: "tenant not found",
		},
		{
			Name:     "malformed tenant",
			TenantID: "malformed",

			OmitRequestBody: true,

			ExpectedLogCount:      0,
			ExpectedStatusCode:    http.StatusBadRequest,
			ExpectedStatusMessage: "tenant_id must be a valid uuid4",
		},
		{
			Name:     "broken db",
			TenantID: "6eb4710c-72df-4941-984d-f2cf3dbe396e",

			OmitRequestBody:  true,
			SimulateBrokenDB: true,

			ExpectedLogCount:      0,
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

			var req *http.Request
			if currentTest.OmitRequestBody {
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/tenants/%s/audit_logs", currentTest.TenantID), nil)
			} else {
				body, err := json.Marshal(currentTest.RequestBody)
				s.Require().NoError(err)

				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/tenants/%s/audit_logs", currentTest.TenantID), bytes.NewReader(body))
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
				var responseBody models.AuditLogs
				err := json.Unmarshal(rec.Body.Bytes(), &responseBody)
				s.Require().NoError(err)

				s.Assert().Len(responseBody, currentTest.ExpectedLogCount)
			}
		})
	}
}
