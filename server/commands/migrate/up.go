package migrate

import (
	"github.com/spf13/cobra"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/persistence"
	"log"
)

func NewMigrateUpCommand() *cobra.Command {
	var configFile string

	cmd := &cobra.Command{
		Use:   "up",
		Short: "migrate the database up",
		Long:  "Running all migrations to bring the database up to date",
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("migrating database up")

			cfg, err := config.Load(&configFile)
			if err != nil {
				log.Fatal(err)
			}

			persister, err := persistence.NewDatabase(cfg.Database)
			if err != nil {
				log.Fatal(err)
			}

			err = persister.MigrateUp()
			if err != nil {
				log.Fatal(err)
			}
		},
	}

	cmd.Flags().StringVar(&configFile, "config", config.DefaultConfigFilePath, "config file")

	return cmd
}
