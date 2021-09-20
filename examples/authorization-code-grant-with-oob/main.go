package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"go.n0stack.dev/lib/openid/configuration"
	oidc "go.n0stack.dev/lib/openid/connect"
	"go.n0stack.dev/lib/openid/connect/authenticator"
	"go.n0stack.dev/lib/openid/examples"
)

func AuthorizationCodeExample(ctx context.Context) (*oidc.Token, error) {
	conf, err := configuration.Fetch(ctx, examples.ExampleIssuer)
	if err != nil {
		return nil, fmt.Errorf(`configuration.Fetch(ctx, auth.OIDC_ISSUER) %w`, err)
	}

	authz := authenticator.Begin(conf).PublicClient(examples.ClientPublic).AuthorizationCodeGrant(authenticator.OOBRedirectURI, authenticator.PKCE_CODE_CHALLENGE_METHOD_S256)
	authCodeURL, err := authz.AuthCodeURL()
	if err != nil {
		return nil, fmt.Errorf(`code.AuthCodeURL() %w`, err)
	}

	fmt.Fprintf(os.Stdout, "Open the following link in your browser:\n\n\t%s\n\n", authCodeURL)

	fmt.Printf("Enter verification code: ")
	code := ""
	if _, err := fmt.Scan(&code); err != nil {
		return nil, err
	}

	ts, err := authz.Exchange(ctx, code, authenticator.SkipStateCheck)
	if err != nil {
		return nil, err
	}

	token, err := ts.Token(ctx)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func main() {
	ctx := context.Background()

	token, err := AuthorizationCodeExample(ctx)
	if err != nil {
		log.Fatalf(`AuthorizationCodeExample(ctx) %v`, err)
	}

	log.Printf("Got token %v", token)
}
