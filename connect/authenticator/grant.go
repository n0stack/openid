package authenticator

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	oidc "go.n0stack.dev/lib/openid/connect"
)

var _ Authentication = &OIDCAuthenticator{}

func (a *OIDCAuthenticator) ClientCredentialsGrant() oidc.TokenSource {
	out := NewRefreshTokenSource(nil, func(ctx context.Context, _ *oidc.Token) (*oidc.Token, error) {
		values := url.Values{}
		values.Set("grant_type", "client_credentials")
		values.Set("scope", strings.Join(a.scope, " "))

		for _, fn := range a.onTokenRequest {
			if err := fn(values); err != nil {
				return nil, fmt.Errorf(`fn(values) %w`, err)
			}
		}

		token, err := obtainToken(ctx, a.Config.TokenEndpoint, values)
		if err != nil {
			return nil, fmt.Errorf(`obtainToken(ctx, c.TokenEndpoint, values) %w`, err)
		}

		return token, nil
	})

	return out
}

func (a *OIDCAuthenticator) RefreshTokenGrant(token *oidc.Token) oidc.TokenSource {
	out := NewRefreshTokenSource(token, func(ctx context.Context, token *oidc.Token) (*oidc.Token, error) {
		values := url.Values{}
		values.Set("grant_type", "refresh_token")
		values.Set("refresh_token", token.RefreshToken)

		for _, fn := range a.onTokenRequest {
			if err := fn(values); err != nil {
				return nil, fmt.Errorf(`fn(values) %w`, err)
			}
		}

		got, err := obtainToken(ctx, a.Config.TokenEndpoint, values)
		if err != nil {
			return nil, fmt.Errorf(`obtainToken(ctx, c.TokenEndpoint, values) %w`, err)
		}

		return got, nil
	})

	return out
}
