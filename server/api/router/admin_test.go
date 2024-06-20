package router

import (
	"github.com/stretchr/testify/suite"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/test"
	"net/http"
	"net/http/httptest"
	"testing"
)

type adminSuite struct {
	test.Suite
}

func TestAdminRouteSuite(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(adminSuite))
}

func (s *adminSuite) TestAdminRouter_New() {
	adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)
	s.Assert().NotEmpty(adminRouter)
}

func (s *adminSuite) TestAdminRouter_Status() {
	s.SkipOnShort()

	tests := []struct {
		Name string

		SimulateBrokenDB bool

		ExpectedStatusCode int
	}{
		{
			Name: "success",

			ExpectedStatusCode: http.StatusOK,
		},
		{
			Name: "broken db",

			SimulateBrokenDB: true,

			ExpectedStatusCode: http.StatusInternalServerError,
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)
			req := httptest.NewRequest(http.MethodGet, "/", nil)

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDB {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			adminRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
		})
	}
}

func (s *adminSuite) TestAdminRouter_Alive() {
	s.SkipOnShort()

	tests := []struct {
		Name string

		SimulateBrokenDB bool

		ExpectedStatusCode        int
		ExpectedStatusMessage     string
		ExpectedStatusContentType string
	}{
		{
			Name: "success",

			ExpectedStatusCode:        http.StatusOK,
			ExpectedStatusMessage:     "{\"alive\":true}\n",
			ExpectedStatusContentType: "application/json; charset=UTF-8",
		},
		{
			Name: "broken db but still alive",

			SimulateBrokenDB: true,

			ExpectedStatusCode:        http.StatusOK,
			ExpectedStatusMessage:     "{\"alive\":true}\n",
			ExpectedStatusContentType: "application/json; charset=UTF-8",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)
			req := httptest.NewRequest(http.MethodGet, "/health/alive", nil)

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDB {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			adminRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)
			s.Assert().Equal(currentTest.ExpectedStatusContentType, rec.Header().Get("Content-Type"))
		})
	}
}

func (s *adminSuite) TestAdminRouter_Ready() {
	s.SkipOnShort()

	tests := []struct {
		Name string

		SimulateBrokenDB bool

		ExpectedStatusCode        int
		ExpectedStatusMessage     string
		ExpectedStatusContentType string
	}{
		{
			Name: "success",

			ExpectedStatusCode:        http.StatusOK,
			ExpectedStatusMessage:     "{\"ready\":true}\n",
			ExpectedStatusContentType: "application/json; charset=UTF-8",
		},
		{
			Name: "broken db but still alive",

			SimulateBrokenDB: true,

			ExpectedStatusCode:        http.StatusOK,
			ExpectedStatusMessage:     "{\"ready\":true}\n",
			ExpectedStatusContentType: "application/json; charset=UTF-8",
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.Name, func() {
			adminRouter := NewAdminRouter(&config.Config{}, s.Storage, nil)
			req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)

			rec := httptest.NewRecorder()

			if currentTest.SimulateBrokenDB {
				err := s.Storage.MigrateDown(-1)
				s.Require().NoError(err)
			}

			adminRouter.ServeHTTP(rec, req)

			s.Assert().Equal(currentTest.ExpectedStatusCode, rec.Code)
			s.Assert().Contains(rec.Body.String(), currentTest.ExpectedStatusMessage)
			s.Assert().Equal(currentTest.ExpectedStatusContentType, rec.Header().Get("Content-Type"))
		})
	}
}
