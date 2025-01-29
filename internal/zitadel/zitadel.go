package zitadel

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var errUnexpectedZitadelStatusCode = errors.New("unexpected ZITADEL status code")

// Client denoates a zitadel client able to interact with the zitadel API.
type Client struct {
	grpc *client.Client

	httpAddr       *url.URL
	http           *http.Client
	httpNoRedirect *http.Client
	jwtSigner      jose.Signer
}

type ZitadelOptions func(c *Client) error

func New(options ...ZitadelOptions) (*Client, error) {
	c := &Client{}
	for _, fn := range options {
		err := fn(c)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func NewMachineClient(ctx context.Context, address *url.URL, machineAccessToken string) (*client.Client, error) {
	api, err := client.New(ctx,
		zitadel.New(address.Hostname(), zitadelOpts(address)...),
		client.WithAuth(client.PAT(machineAccessToken)),
	)
	if err != nil {
		return nil, fmt.Errorf("creating zitadel client: %w", err)
	}
	return api, nil
}

// WithHTTP initializes a http client connection on the zitadel client.
// Stores the address to use for http requests to the API.
func WithHTTP(u *url.URL) ZitadelOptions {
	return func(c *Client) error {
		c.httpAddr = u
		c.http = http.DefaultClient
		c.httpNoRedirect = &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		}
		return nil
	}
}

// WithGRPC initializes a gRPC client connection on the zitadel client.
func WithGRPC(ctx context.Context, u *url.URL, machineAccessToken string) ZitadelOptions {
	return func(c *Client) error {
		conn, err := client.New(ctx,
			zitadel.New(u.Hostname(), zitadelOpts(u)...),
			client.WithAuth(client.PAT(machineAccessToken)),
		)
		if err != nil {
			return fmt.Errorf("creating zitadel gRPC client: %w", err)
		}
		c.grpc = conn
		return nil
	}
}

type jwtKey struct {
	Type     string `json:"type"`
	KeyId    string `json:"keyId"`
	Key      string `json:"key"`
	AppId    string `json:"appId"`
	ClientId string `json:"clientId"`
}

// WithJWTAuthentication instructs the zitadel client to use JWT authentication.
func WithJWTAuthentication(jwt string) ZitadelOptions {
	return func(c *Client) error {
		if jwt == "" {
			return nil
		}

		var jwtKey jwtKey
		if err := json.Unmarshal([]byte(jwt), &jwtKey); err != nil {
			return fmt.Errorf("unmarshaling JWT key: %w", err)
		}

		block, _ := pem.Decode([]byte(jwtKey.Key))
		if block == nil {
			return fmt.Errorf("empty JWT key: %v", jwtKey.Key)
		}

		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing JWT key: %w", err)
		}

		c.jwtSigner, err = jose.NewSigner(jose.SigningKey{Key: key, Algorithm: "RS256"}, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]any{
				"kid": jwtKey.KeyId,
			},
		})
		if err != nil {
			return fmt.Errorf("creating JWT signer: %w", err)
		}
		return nil
	}
}

func (c *Client) newHTTPRequestURL(path string) (*url.URL, error) {
	u, err := url.Parse(c.httpAddr.String() + path)
	if err != nil {
		return nil, fmt.Errorf("creating request URL: %w", err)
	}
	return u, nil
}

// doHTTPRequestWithDefaultClient returns the HTTP response body.
func (c *Client) doHTTPRequestWithDefaultClient(req *http.Request) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doing HTTP request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d", errUnexpectedZitadelStatusCode, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return data, nil
}

// doHTTPRequestWithNoRedirect returns the redirect location URL of the HTTP response header.
func (c *Client) doHTTPRequestWithNoRedirect(req *http.Request) (*url.URL, error) {
	resp, err := c.httpNoRedirect.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doing HTTP request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("%w: %d", errUnexpectedZitadelStatusCode, resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		return nil, fmt.Errorf("reading Location header: %w", err)
	}
	return loc, nil
}

func newJSONGetRequest(ctx context.Context, reqURL *url.URL) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func codeFromCallbackURL(u string) (string, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return "", fmt.Errorf("parsing URL: %w", err)
	}
	return parsedURL.Query().Get("code"), nil
}

func SanitizeURL(addr string) (*url.URL, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" {
		u.Scheme = "https"
	}
	return u, nil
}

// zitadelOpts sets the insecure option if the address scheme is 'http'.
func zitadelOpts(u *url.URL) []zitadel.Option {
	zitadelOpts := make([]zitadel.Option, 0, 1)
	if u.Scheme == "http" {
		zitadelOpts = append(zitadelOpts, zitadel.WithInsecure(u.Port()))
	}
	return zitadelOpts
}
