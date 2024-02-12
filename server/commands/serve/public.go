package serve

import (
	"github.com/spf13/cobra"
	"github.com/teamhanko/passkey-server/api"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/mapper"
	"github.com/teamhanko/passkey-server/persistence"
	"log"
	"sync"
)

func NewServePublicCommand() *cobra.Command {
	var (
		configFile                string
		authenticatorMetadataFile string
	)

	cmd := &cobra.Command{
		Use:   "public",
		Short: "Start the passkey server REST API",
		Long:  "Serving all endpoints for using the passkey server REST API",
		Run: func(cmd *cobra.Command, args []string) {
			globalConfig, err := config.Load(&configFile)
			if err != nil {
				log.Fatal(err)
			}

			authenticatorMetadata := mapper.LoadAuthenticatorMetadata(&authenticatorMetadataFile)

			persister, err := persistence.NewDatabase(globalConfig.Database)
			if err != nil {
				log.Fatal(err)
			}

			var wg sync.WaitGroup
			wg.Add(1)

			go api.StartPublic(globalConfig, &wg, persister, authenticatorMetadata)

			wg.Wait()
		},
	}

	cmd.Flags().StringVar(&configFile, "config", config.DefaultConfigFilePath, "config file")
	cmd.Flags().StringVar(&authenticatorMetadataFile, "auth-meta", "", "authenticator metadata file")

	return cmd
}
