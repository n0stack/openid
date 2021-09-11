package authenticator

import (
	"net/url"

	"go.n0stack.dev/lib/openid/configuration"
)

type OIDCAuthenticator struct {
	Config *configuration.OpenIDConfiguration

	scope []string

	onAuthorizationRequest []func(url.Values) error
	onTokenRequest         []func(url.Values) error
}

func Begin(config *configuration.OpenIDConfiguration) ClientAuthentication {
	out := &OIDCAuthenticator{
		Config:                 config,
		onAuthorizationRequest: make([]func(url.Values) error, 0, 5),
		onTokenRequest:         make([]func(url.Values) error, 0, 5),
		scope:                  []string{"openid"},
	}

	return out
}

func (a *OIDCAuthenticator) SetScope(scope []string) {
	a.scope = scope
}

func (a *OIDCAuthenticator) Clone() *OIDCAuthenticator {
	out := &OIDCAuthenticator{
		Config:                 a.Config,
		scope:                  a.scope,
		onAuthorizationRequest: a.onAuthorizationRequest,
		onTokenRequest:         a.onTokenRequest,
	}

	return out
}

// func FromOauth2Config(config oauth2.Config, pkce PKCECodeChallengeMethod) AuthorizationCodeGrant {
// 	auth := Begin(&configuration.OpenIDConfiguration{
// 		AuthorizationEndpoint: config.Endpoint.AuthURL,
// 		TokenEndpoint:         config.Endpoint.TokenURL,
// 	})
// 	// auth.With("scope")

// 	return auth.ClientSecret(config.ClientID, config.ClientSecret).AuthorizationCodeGrant(config.RedirectURL, pkce)
// }
