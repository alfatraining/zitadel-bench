package main

import (
	"context"
	"fmt"
	"log"

	"github.com/alfatraining/zitadel-bench/cmd/cli/pflagutil"
	"github.com/alfatraining/zitadel-bench/internal/zitadel"
	"github.com/spf13/cobra"
)

type createUsersConfig struct {
	*zitadel.CreateUsersRequest

	usernamePrefix string
	numUsers       int
}

func createUsersCmd(zitadelAddress *string, helpEnv *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-users",
		Short: "Create multiple users at once in a running ZITADEL instance",
		Long: `Creates a given number of users with a given username prefix and given password
in a single command.

Users of this command have to additionally specify a machine access token with
the IAM_OWNER role or equivalent and the organization the users will be created in.

Usernames are constructed such that, for example, for the prefix 'test', the first
username will be 'test0@example.com', the second 'test1@example.com' and so on.`,
	}

	conf := createUsersConfig{CreateUsersRequest: &zitadel.CreateUsersRequest{
		Address: *zitadelAddress,
	}}
	cmd.Flags().StringVar(&conf.CreateUsersRequest.MachineAccessToken, "machine-access-token", "", "Access token of a machine user having the required permissions to create users")
	cmd.Flags().StringVar(&conf.CreateUsersRequest.Organization, "organization", "", "Organization the users are created in")
	cmd.Flags().StringVar(&conf.usernamePrefix, "username-prefix", "", "Username prefix (resulting usernames will be: {UsernamePrefix}{Num}@example.com)")
	cmd.Flags().StringVar(&conf.CreateUsersRequest.Password, "password", "", "Password of the created users")
	cmd.Flags().IntVar(&conf.numUsers, "num-users", 1, "Number of users to create")
	if err := pflagutil.PopulateFromEnv(cmd.Flags()); err != nil {
		log.Fatal("populating config from env:", err)
	}

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if *helpEnv {
			pflagutil.PrintEnvUsage(cmd.Flags())
			return nil
		}

		if err := createUsers(cmd.Context(), conf); err != nil {
			return fmt.Errorf("creating users: %w", err)
		}
		return nil
	}
	return cmd
}

func createUsers(ctx context.Context, conf createUsersConfig) error {
	u, err := zitadel.SanitizeURL(conf.CreateUsersRequest.Address)
	if err != nil {
		return err
	}

	client, err := zitadel.New(
		zitadel.WithHTTP(u),
		zitadel.WithGRPC(ctx, u, conf.CreateUsersRequest.MachineAccessToken),
	)

	for i := range conf.numUsers {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		req := conf.CreateUsersRequest.SetUserAndEmail(conf.usernamePrefix, i)
		if err := client.CreateUser(ctx, req); err != nil {
			return fmt.Errorf("creating user %d: %w", i, err)
		}
		if (i+1)%10 == 0 {
			log.Printf("created %d/%d users", i+1, conf.numUsers)
		}
	}
	log.Printf("All users created. First user is: %q", zitadel.UserEmail(conf.usernamePrefix, 0))
	return nil
}
