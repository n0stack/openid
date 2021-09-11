package authenticator

import (
	"context"
	"fmt"
	"time"

	oidc "go.n0stack.dev/lib/openid/connect"
)

type RefreshTokenSource struct {
	token     *oidc.Token
	refresher func(ctx context.Context, token *oidc.Token) (*oidc.Token, error)

	TokenRefreshMargin time.Duration

	now        func() time.Time
	nextUpdate time.Time
}

func NewRefreshTokenSource(
	token *oidc.Token,
	refresher func(ctx context.Context, token *oidc.Token) (*oidc.Token, error),
) *RefreshTokenSource {
	out := &RefreshTokenSource{
		token:     token,
		refresher: refresher,

		TokenRefreshMargin: 1 * time.Minute,

		now:        time.Now,
		nextUpdate: time.Now(),
	}

	return out
}

func (ts *RefreshTokenSource) Token(ctx context.Context) (*oidc.Token, error) {
	if ts.nextUpdate.After(ts.now()) {
		t, err := ts.refresher(ctx, ts.token)
		if err != nil {
			return nil, fmt.Errorf(`ts.refresher(ctx, ts.token) %w`, err)
		}

		ts.token = t
		ts.nextUpdate = ts.now().Add(time.Duration(t.ExpiresIn)*time.Second - ts.TokenRefreshMargin)
	}

	return ts.token, nil
}
