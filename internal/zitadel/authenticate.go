package zitadel

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/crypto"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	oidcpb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/oidc/v2"
	sessionpb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2"
)

const (
	codeVerifierLength         = 64
	responseTypeCode           = "code"
	grantTypeAuthorizationCode = "authorization_code"
	requestedScopes            = "email profile offline_access"
	clientAssertionTypeJWT     = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// AuthRequest stores required parameters for an authentication workflow.
type AuthRequest struct {
	Address            string
	MachineAccessToken string
	MachineUserID      string
	ClientID           string
	PrivateKey         string
	RedirectURI        string
	Username           string
	Password           string
	Count              int
	Concurrency        int
}

// AuthResponse is the authentication response returned from zitadel
// (containing, for example, the AccessToken and ExpiresIn).
type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

type session struct {
	id    string
	token string
}

type codeExchangeRequest struct {
	code                string
	codeVerifier        string
	redirectURI         string
	applicationClientID string
}

func (r codeExchangeRequest) toRawQuery() string {
	const grantTypeAuthorizationCode = "authorization_code"
	values := make(url.Values)
	values.Set("code", r.code)
	values.Set("grant_type", grantTypeAuthorizationCode)
	values.Set("redirect_uri", r.redirectURI)
	values.Set("code_verifier", r.codeVerifier)
	values.Set("client_id", r.applicationClientID)
	return values.Encode()
}

type authorizeRequest struct {
	clientID            string
	redirectURI         *url.URL
	responseType        string
	scopes              []string
	codeChallenge       string
	codeChallengeMethod string
}

func (r authorizeRequest) toRawQuery() string {
	q := make(url.Values)
	q.Set("client_id", r.clientID)
	q.Set("redirect_uri", r.redirectURI.String())
	q.Set("response_type", r.responseType)
	q.Set("scope", strings.Join(r.scopes, " "))
	q.Set("code_challenge", r.codeChallenge)
	q.Set("code_challenge_method", r.codeChallengeMethod)
	return q.Encode()
}

func newCodeChallenge(codeVerifier string) string {
	hasher := sha256.New()
	hasher.Write([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
}

func random(length int) string {
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	chars += "abcdefghijklmnopqrstuvwxyz"
	chars += "0123456789"

	runes := []rune(chars)
	out := make([]rune, length)
	for i := range out {
		out[i] = runes[rand.Intn(len(runes))]
	}
	return string(out)
}

func (c *Client) UsernamePasswordAuthenticate(ctx context.Context, req *AuthRequest) (AuthResponse, error) {
	// based on https://zitadel.com/docs/guides/integrate/login-ui/oidc-standard
	if c.jwtSigner != nil {
		return c.jwt(ctx, req)
	}
	return c.pkcse(ctx, req)
}

func (c *Client) usernamePasswordAuthenticate(ctx context.Context, req *AuthRequest, authorizeRequestURLParams string, codeExchangeRequestURLParams func(code string) string) (AuthResponse, error) {
	authRequestID, err := c.requestAuthRequestID(ctx, req, authorizeRequestURLParams)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("requesting auth request ID: %w", err)
	}

	session, err := c.createSession(ctx, req)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("creating session: %w", err)
	}

	code, err := c.getCode(ctx, authRequestID, session)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("getting code: %w", err)
	}

	authResponse, err := c.exchangeCodeForToken(ctx, codeExchangeRequestURLParams(code))
	if err != nil {
		return AuthResponse{}, fmt.Errorf("exchanging code: %w", err)
	}

	return authResponse, nil
}

func (c *Client) pkcse(ctx context.Context, req *AuthRequest) (AuthResponse, error) {
	const (
		codeChallengeMethodS256 = "S256"
		responseTypeCode        = "code"
	)

	codeVerifier := random(codeVerifierLength)
	codeChallenge := newCodeChallenge(codeVerifier)

	authorizeRequestURLParams := url.Values{
		"client_id":             []string{req.ClientID},
		"redirect_uri":          []string{req.RedirectURI},
		"response_type":         []string{responseTypeCode},
		"scope":                 []string{requestedScopes},
		"code_challenge":        []string{codeChallenge},
		"code_challenge_method": []string{codeChallengeMethodS256},
	}.Encode()

	codeExchangeRequestURLParams := func(code string) string {
		return url.Values{
			"code":          []string{code},
			"grant_type":    []string{grantTypeAuthorizationCode},
			"redirect_uri":  []string{req.RedirectURI},
			"code_verifier": []string{codeVerifier},
			"client_id":     []string{req.ClientID},
		}.Encode()
	}
	return c.usernamePasswordAuthenticate(ctx, req, authorizeRequestURLParams, codeExchangeRequestURLParams)
}

func (c *Client) jwt(ctx context.Context, req *AuthRequest) (AuthResponse, error) {
	claims := &oidc.TokenClaims{
		Audience:     oidc.Audience{req.Address},
		Expiration:   oidc.FromTime(time.Now().Add(time.Minute)),
		IssuedAt:     oidc.FromTime(time.Now()),
		Issuer:       req.ClientID,
		Subject:      req.ClientID,
		SignatureAlg: jose.RS256,
	}

	clientAssertion, err := crypto.Sign(claims, c.jwtSigner)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("signing JWT: %w", err)
	}

	authorizeRequestURLParams := url.Values{
		"client_id":     []string{req.ClientID},
		"redirect_uri":  []string{req.RedirectURI},
		"response_type": []string{responseTypeCode},
		"scope":         []string{requestedScopes},
	}.Encode()

	codeExchangeRequestURLParams := func(code string) string {
		return url.Values{
			"code":                  []string{code},
			"grant_type":            []string{grantTypeAuthorizationCode},
			"redirect_uri":          []string{req.RedirectURI},
			"client_assertion":      []string{clientAssertion},
			"client_assertion_type": []string{clientAssertionTypeJWT},
		}.Encode()
	}
	return c.usernamePasswordAuthenticate(ctx, req, authorizeRequestURLParams, codeExchangeRequestURLParams)
}

func (c *Client) requestAuthRequestID(ctx context.Context, req *AuthRequest, authReqURLParams string) (string, error) {
	// see https://zitadel.com/docs/apis/openidoauth/endpoints#authorization_endpoint
	reqURL, err := c.newHTTPRequestURL("/oauth/v2/authorize")
	if err != nil {
		return "", err
	}

	reqURL.RawQuery = authReqURLParams
	httpReq, err := newJSONGetRequest(ctx, reqURL)
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("X-Zitadel-Login-Client", req.MachineUserID)

	loc, err := c.doHTTPRequestWithNoRedirect(httpReq)
	if err != nil {
		return "", err
	}
	authRequest := loc.Query().Get("authRequest")
	return authRequest, nil
}

func (c *Client) createSession(ctx context.Context, req *AuthRequest) (session, error) {
	sessionReq := &sessionpb.CreateSessionRequest{
		Checks: &sessionpb.Checks{
			User:     &sessionpb.CheckUser{Search: &sessionpb.CheckUser_LoginName{LoginName: req.Username}},
			Password: &sessionpb.CheckPassword{Password: req.Password},
		},
	}
	resp, err := c.grpc.SessionServiceV2().CreateSession(ctx, sessionReq)
	if err != nil {
		return session{}, fmt.Errorf("creating session: %w", err)
	}

	return session{
		id:    resp.GetSessionId(),
		token: resp.GetSessionToken(),
	}, nil
}

func (c *Client) getCode(ctx context.Context, authRequestID string, session session) (string, error) {
	oidcReq := &oidcpb.CreateCallbackRequest{
		AuthRequestId: authRequestID,
		CallbackKind: &oidcpb.CreateCallbackRequest_Session{
			Session: &oidcpb.Session{
				SessionId:    session.id,
				SessionToken: session.token,
			},
		},
	}
	resp, err := c.grpc.OIDCServiceV2().CreateCallback(ctx, oidcReq)
	if err != nil {
		return "", fmt.Errorf("creating callback: %w", err)
	}

	return codeFromCallbackURL(resp.GetCallbackUrl())
}

func (c *Client) exchangeCodeForToken(ctx context.Context, exchangeReqURLParams string) (AuthResponse, error) {
	// see https://zitadel.com/docs/apis/openidoauth/endpoints#authorization-code-grant-code-exchange
	reqURL, err := c.newHTTPRequestURL("/oauth/v2/token")
	if err != nil {
		return AuthResponse{}, err
	}
	reqURL.RawQuery = exchangeReqURLParams
	httpReq, err := newJSONGetRequest(ctx, reqURL)
	if err != nil {
		return AuthResponse{}, err
	}
	data, err := c.doHTTPRequestWithDefaultClient(httpReq)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("doing HTTP request: %w", err)
	}
	var t AuthResponse
	if err = json.Unmarshal(data, &t); err != nil {
		return AuthResponse{}, fmt.Errorf("decoding token response: %w", err)
	}

	return t, nil
}
