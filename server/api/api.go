package api

import (
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/router"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/persistence"
	"sync"
)

func StartPublic(cfg *config.Config, wg *sync.WaitGroup, persister persistence.Persister) {
	defer wg.Done()

	mainRouter := router.NewMainRouter(cfg, persister)
	mainRouter.Logger.Fatal(mainRouter.Start(cfg.Address))
}

func StartAdmin(cfg *config.Config, wg *sync.WaitGroup, persister persistence.Persister, prometheus echo.MiddlewareFunc) {
	defer wg.Done()

	adminRouter := router.NewAdminRouter(cfg, persister, prometheus)
	adminRouter.Logger.Fatal(adminRouter.Start(cfg.AdminAddress))
}
