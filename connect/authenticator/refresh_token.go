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
		now:                time.Now,
		TokenRefreshMargin: 1 * time.Minute,

		token:     token,
		refresher: refresher,
	}

	return out
}

func (ts *RefreshTokenSource) Token(ctx context.Context) (*oidc.Token, error) {
	if ts.nextUpdate.Before(ts.now()) {
		t, err := ts.refresher(ctx, ts.token)
		if err != nil {
			return nil, fmt.Errorf(`ts.refresher(ctx, ts.token) %w`, err)
		}

		ts.token = t
		ts.nextUpdate = ts.now().Add(time.Duration(t.ExpiresIn)*time.Second - ts.TokenRefreshMargin)
	}

	return ts.token, nil
}
