package jwk

import "github.com/spf13/cobra"

func NewJwkCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "jwk",
		Short: "Tools for handling JSON Web Keys",
		Long:  ``,
	}
}

func RegisterCommands(parent *cobra.Command) {
	cmd := NewJwkCommand()
	parent.AddCommand(cmd)
	cmd.AddCommand(NewCreateCommand())
}
