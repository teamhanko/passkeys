package serve

import (
	"github.com/spf13/cobra"
	"github.com/teamhanko/passkey-server/config"
)

func NewServeCommand() *cobra.Command {
	var configFile string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the passkey server",
		Long:  "",
	}

	cmd.Flags().StringVar(&configFile, "config", config.DefaultConfigFilePath, "config file")

	return cmd
}

func RegisterCommands(parent *cobra.Command) {
	cmd := NewServeCommand()
	cmd.AddCommand(NewServePublicCommand())
	cmd.AddCommand(NewServeAdminApiCommand())
	cmd.AddCommand(NewServeAllCommand())

	parent.AddCommand(cmd)
}
