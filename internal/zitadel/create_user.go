package zitadel

import (
	"context"
	"fmt"

	objectpb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	userpb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
)

type CreateUsersRequest struct {
	// Email and Username are determined by UsernamePrefix.
	Email              string
	UserName           string
	Address            string
	MachineAccessToken string
	Organization       string
	Password           string
}

// CreateUser creates a human zitadel user.
func (c *Client) CreateUser(ctx context.Context, req CreateUsersRequest) error {
	_, err := c.grpc.UserServiceV2().AddHumanUser(ctx, &userpb.AddHumanUserRequest{
		Organization: &objectpb.Organization{Org: &objectpb.Organization_OrgId{OrgId: req.Organization}},
		Email: &userpb.SetHumanEmail{
			Email:        req.Email,
			Verification: &userpb.SetHumanEmail_IsVerified{IsVerified: true},
		},
		PasswordType: &userpb.AddHumanUserRequest_Password{Password: &userpb.Password{Password: req.Password}},
		Profile: &userpb.SetHumanProfile{
			GivenName:  req.UserName,
			FamilyName: "zitcli-created",
		},
	})
	return err
}

// SetUserAndEmail sets the Username and Email field based on the prefix and i.
// It returns a copy of the struct.
func (user *CreateUsersRequest) SetUserAndEmail(prefix string, i int) CreateUsersRequest {
	req := *user
	req.UserName = Username(prefix, i)
	req.Email = UserEmail(prefix, i)
	return req
}

func Username(prefix string, i int) string {
	return fmt.Sprintf("%s %d", prefix, i)
}

func UserEmail(prefix string, i int) string {
	return fmt.Sprintf("%s-%d@example.com", prefix, i)
}
