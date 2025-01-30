package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/alfatraining/zitadel-bench/cmd/cli/pflagutil"
	"github.com/spf13/cobra"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	err := rootCmd().ExecuteContext(ctx)
	if err != nil {
		log.Fatal(err)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zitcli",
		Short: "ZITADEL CLI Client",
		Long: `This is a CLI client to ZITADEL that offers features like mass user creation or a repetitive authentication.
All flag arguments can be alternatively provided through SCREAMING_SNAKE_CASE environment vars, replace dashes (-) with underscores (_).`,
		SilenceUsage: true,
	}

	zitadelAddress := cmd.PersistentFlags().String("addr", "http://localhost:8080", "ZITADEL address. 'http' will use an insecure connection.")
	helpEnv := cmd.PersistentFlags().Bool("help-env", false, "Display environment config help")
	if err := pflagutil.PopulateFromEnv(cmd.PersistentFlags()); err != nil {
		log.Fatal("populating config from env:", err)
	}
	// We need to pass the persistent flag values by reference because they are only parsed when the root command is actually executed.
	cmd.AddCommand(authenticateCmd(zitadelAddress, helpEnv))
	cmd.AddCommand(createUsersCmd(zitadelAddress, helpEnv))

	return cmd
}
