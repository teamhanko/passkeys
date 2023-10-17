package api

import (
	router2 "github.com/teamhanko/passkey-server/api/router"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/persistence"
	"sync"
)

func Start(cfg *config.Config, wg *sync.WaitGroup, persister persistence.Persister) {
	defer wg.Done()

	router := router2.NewMainRouter(cfg, persister)
	router.Logger.Fatal(router.Start(cfg.Server.Address))
}
