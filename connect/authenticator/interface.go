package authenticator

import (
	"context"
	"crypto/rsa"

	oidc "go.n0stack.dev/lib/openid/connect"
)

type OIDCOptions interface {
	SetScope(scope []string)

	// WithParam(key, value string)
}

type ClientAuthentication interface {
	OIDCOptions

	// RFC 7636: Proof Key for Code Exchange by OAuth Public Clients
	PublicClient(clientID string) Authentication

	// RFC 6749: The OAuth 2.0 Authorization Framework
	ClientSecret(clientID string, clientSecret string) Authentication

	// RFC 7523: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants
	ClientBearerJWT(clientID string, privateKey *rsa.PrivateKey) Authentication
}

// RFC7636: Proof Key for Code Exchange by OAuth Public Clients
type PKCECodeChallengeMethod string

const (
	PKCE_CODE_CHALLENGE_METHOD_S256 PKCECodeChallengeMethod = "S256"
)

type Authentication interface {
	OIDCOptions

	// https://tools.ietf.org/html/rfc6749#section-4.4
	ClientCredentialsGrant() oidc.TokenSource

	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
	// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
	AuthorizationCodeGrant(redirectURL string, method PKCECodeChallengeMethod) AuthorizationCodeGrant

	RefreshTokenGrant(token *oidc.Token) oidc.TokenSource
}

const OOBRedirectURI = "urn:ietf:wg:oauth:2.0:oob"

type AuthorizationCodeGrant interface {
	// https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
	AuthCodeURL() (string, error)

	// https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
	Exchange(ctx context.Context, code string, state string) (oidc.TokenSource, error)
}
