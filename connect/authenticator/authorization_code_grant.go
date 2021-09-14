package authenticator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	oidc "go.n0stack.dev/lib/openid/connect"
)

type authorizationCodeGrant struct {
	*OIDCAuthenticator

	state string
}

// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
func (a *OIDCAuthenticator) AuthorizationCodeGrant(redirectURL string, method PKCECodeChallengeMethod) AuthorizationCodeGrant {
	out := &authorizationCodeGrant{
		OIDCAuthenticator: a,
	}

	codeVerifier := randString(128)
	codeChallenge := ""
	switch method {
	case PKCE_CODE_CHALLENGE_METHOD_S256:
		hashed := sha256.Sum256([]byte(codeVerifier))
		codeChallenge = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hashed[:])
	}

	out.state = randString(64)
	out.onAuthorizationRequest = append(out.onAuthorizationRequest, func(values url.Values) error {
		values.Set("redirect_uri", redirectURL)
		values.Set("state", out.state)
		values.Set("code_challenge_method", string(method))
		values.Set("code_challenge", codeChallenge)
		return nil
	})
	out.onTokenRequest = append(out.onTokenRequest, func(values url.Values) error {
		values.Set("redirect_uri", redirectURL)
		values.Set("code_verifier", codeVerifier)
		return nil
	})

	return out
}

// https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
func (a *authorizationCodeGrant) AuthCodeURL() (string, error) {
	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("scope", strings.Join(a.scope, " "))
	for _, fn := range a.onAuthorizationRequest {
		if err := fn(values); err != nil {
			return "", fmt.Errorf(`fn(values) %w`, err)
		}
	}

	var buf bytes.Buffer
	buf.WriteString(a.Config.AuthorizationEndpoint)
	if strings.Contains(a.Config.AuthorizationEndpoint, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(values.Encode())

	return buf.String(), nil
}

const SkipStateCheck = "__skip_state_check__"

// https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
func (a *authorizationCodeGrant) Exchange(ctx context.Context, code string, state string) (oidc.TokenSource, error) {
	if state != SkipStateCheck && state != a.state {
		return nil, fmt.Errorf("state is mismatch")
	}

	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Set("code", code)
	for _, fn := range a.onTokenRequest {
		if err := fn(values); err != nil {
			return nil, fmt.Errorf(`fn(values) %w`, err)
		}
	}

	token, err := obtainToken(ctx, a.Config.TokenEndpoint, values)
	if err != nil {
		return nil, fmt.Errorf(`obtainToken(ctx, c.TokenEndpoint, values) %w`, err)
	}

	return a.RefreshTokenGrant(token), nil
}
