package test

import (
	"fmt"
	"github.com/go-testfixtures/testfixtures/v3"
	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/pop/v6/logging"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/suite"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/persistence"
	"testing"
)

type Suite struct {
	suite.Suite
	Storage persistence.Database
	DB      *TestDB
	Name    string // used for database docker container name, so that tests can run in parallel
}

func (s *Suite) SetupSuite() {
	if testing.Short() {
		return
	}
	pop.SetLogger(testLogger)
	if s.Name == "" {
		var err error
		id, err := uuid.NewV4()
		if err != nil {
			s.Fail("failed to generate database container name")
		}
		s.Name = id.String()
	}
	dialect := "postgres"
	db, err := StartDB(s.Name, dialect)
	s.Require().NoError(err)
	storage, err := persistence.NewDatabase(config.Database{
		Url: db.DatabaseUrl,
	})
	s.Require().NoError(err)

	s.Storage = storage
	s.DB = db
}

func (s *Suite) SetupTest() {
	if s.DB != nil {
		err := s.Storage.MigrateUp()
		s.NoError(err)
	}
}

func (s *Suite) TearDownTest() {
	if s.DB != nil {
		err := s.Storage.MigrateDown(-1)
		s.NoError(err)
	}
}

func (s *Suite) TearDownSuite() {
	if s.DB != nil {
		s.NoError(PurgeDB(s.DB))
	}
}

func (s *Suite) SetupSubTest() {
	if s.DB != nil {
		// remove everything before starting a new migration
		err := s.Storage.MigrateDown(-1)
		s.NoError(err)

		err = s.Storage.MigrateUp()
		s.NoError(err)
	}
}

func (s *Suite) TearDownSubTest() {
	if s.DB != nil {
		err := s.Storage.MigrateDown(-1)
		s.NoError(err)
	}

}

// LoadFixtures loads predefined data from the path in the database.
func (s *Suite) LoadFixtures(path string) error {
	fixtures, err := testfixtures.New(
		testfixtures.Database(s.DB.DbCon),
		testfixtures.Dialect(s.DB.Dialect),
		testfixtures.Directory(path),
		testfixtures.SkipResetSequences(),
	)
	if err != nil {
		return fmt.Errorf("could not create testfixtures: %w", err)
	}

	err = fixtures.Load()
	if err != nil {
		return fmt.Errorf("could not load fixtures: %w", err)
	}

	return nil
}

func (s *Suite) LoadMultipleFixtures(paths []string) error {
	for _, path := range paths {
		if err := s.LoadFixtures(path); err != nil {
			return err
		}
	}

	return nil
}

func (s *Suite) SkipOnShort() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode")
	}
}

func testLogger(_ logging.Level, _ string, _ ...interface{}) {

}
