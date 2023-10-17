package migrate

import "github.com/spf13/cobra"

func NewMigrateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Database migration helper",
		Long:  "Migrating the database up or down",
	}
}

func RegisterCommands(parent *cobra.Command) {
	cmd := NewMigrateCommand()
	cmd.AddCommand(NewMigrateUpCommand())
	cmd.AddCommand(NewMigrateDownCommand())

	parent.AddCommand(cmd)
}
