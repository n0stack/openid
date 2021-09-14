package authenticator

import (
	"context"
	"testing"
	"time"

	oidc "go.n0stack.dev/lib/openid/connect"
)

func TestSmallRefresh(t *testing.T) {
	ctx := context.Background()
	ts := NewRefreshTokenSource(
		&oidc.Token{
			AccessToken: "not modified",
			ExpiresIn:   uint32(time.Hour.Seconds()),
		},
		func(ctx context.Context, token *oidc.Token) (*oidc.Token, error) {
			return &oidc.Token{
				AccessToken: "modified",
				ExpiresIn:   uint32(time.Hour.Seconds()),
			}, nil
		},
	)
	if token, err := ts.Token(ctx); err != nil {
		t.Errorf(`ts.Token(ctx)`)
	} else if token.AccessToken != "modified" {
		t.Errorf("token is not updated at first time")
	}

	ts.refresher = func(ctx context.Context, token *oidc.Token) (*oidc.Token, error) {
		return &oidc.Token{
			AccessToken: "modified 2nd time",
			ExpiresIn:   uint32(time.Hour.Seconds()),
		}, nil
	}
	if token, err := ts.Token(ctx); err != nil {
		t.Errorf(`ts.Token(ctx)`)
	} else if token.AccessToken != "modified" {
		t.Errorf("token is updated which is used cache")
	}

	ts.nextUpdate = time.Now().Add(-1 * time.Hour)
	if token, err := ts.Token(ctx); err != nil {
		t.Errorf(`ts.Token(ctx)`)
	} else if token.AccessToken != "modified 2nd time" {
		t.Errorf("token is not updated at second time")
	}
}
