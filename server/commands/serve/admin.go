package serve

import (
	"github.com/spf13/cobra"
	"github.com/teamhanko/passkey-server/api"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/persistence"
	"log"
	"sync"
)

func NewServeAdminApiCommand() *cobra.Command {
	var configFile string

	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Start the passkey server Admin API",
		Long:  "Serving all endpoints for using the passkey server Admin API",
		Run: func(cmd *cobra.Command, args []string) {
			globalConfig, err := config.Load(&configFile)
			if err != nil {
				log.Fatal(err)
			}

			persister, err := persistence.NewDatabase(globalConfig.Database)
			if err != nil {
				log.Fatal(err)
			}

			var wg sync.WaitGroup
			wg.Add(1)

			go api.StartAdmin(globalConfig, &wg, persister, nil)

			wg.Wait()
		},
	}

	cmd.Flags().StringVar(&configFile, "config", config.DefaultConfigFilePath, "config file")

	return cmd
}
