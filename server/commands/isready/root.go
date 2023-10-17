package isready

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/teamhanko/passkey-server/config"
	"log"
	"net"
	"net/http"
	"strings"
)

func NewIsReadyCommand() *cobra.Command {
	var configFile string

	cmd := &cobra.Command{
		Use:   "isready",
		Args:  cobra.NoArgs,
		Short: "Health check of the passkey server",
		Long:  "Checks if the passkey server is healthy. Use /health/ready endpoint to check if the service is ready to accept requests",
		Run: func(command *cobra.Command, args []string) {
			globalConf, err := config.Load(&configFile)
			if err != nil {
				log.Fatal(err)
			}

			host, port, err := net.SplitHostPort(globalConf.Server.Address)
			if err != nil {
				log.Fatalf("Could not parse address %s", globalConf.Server.Address)
			}

			if strings.TrimSpace(host) == "" {
				host = "localhost"
			}

			healthUrl := fmt.Sprintf("http://%s:%s/health/ready", host, port)
			healthResponse, err := http.Get(healthUrl)
			if err != nil || healthResponse.StatusCode != http.StatusOK {
				log.Fatal("Passkey server is not ready")
			} else {
				log.Println("Passkey server is ready")
			}
		},
	}

	cmd.Flags().StringVar(&configFile, "config", config.DefaultConfigFilePath, "config file")

	return cmd
}

func RegisterCommands(parent *cobra.Command) {
	cmd := NewIsReadyCommand()
	parent.AddCommand(cmd)
}
