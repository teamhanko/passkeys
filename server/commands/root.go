package commands

import (
	"github.com/spf13/cobra"
	"github.com/teamhanko/passkey-server/commands/isready"
	"github.com/teamhanko/passkey-server/commands/migrate"
	"github.com/teamhanko/passkey-server/commands/serve"
	"github.com/teamhanko/passkey-server/commands/version"
	"log"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "passkey",
	}

	isready.RegisterCommands(cmd)
	migrate.RegisterCommands(cmd)
	version.RegisterCommands(cmd)
	serve.RegisterCommands(cmd)

	return cmd
}

func Execute() {
	cmd := NewCommand()
	err := cmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
