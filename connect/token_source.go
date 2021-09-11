package oidc

import (
	"context"
)

type TokenSource interface {
	Token(ctx context.Context) (*Token, error)
}
