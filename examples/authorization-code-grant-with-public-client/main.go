package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/pkg/browser"
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

	authz := authenticator.Begin(conf).PublicClient(examples.ClientPublic).AuthorizationCodeGrant("http://localhost:8081/callback", authenticator.PKCE_CODE_CHALLENGE_METHOD_S256)
	authCodeURL, err := authz.AuthCodeURL()
	if err != nil {
		return nil, fmt.Errorf(`code.AuthCodeURL() %w`, err)
	}

	if err := browser.OpenURL(authCodeURL); err != nil {
		log.Printf(`browser.OpenURL(authCodeURL) %v`, err)
	}
	fmt.Fprintf(os.Stdout, "Open the following link in your browser:\n\n\t%s\n\n", authCodeURL)

	redirectChan := make(chan url.Values)
	redirectHandler := http.NewServeMux()
	redirectServer := &http.Server{
		Addr:    ":8081",
		Handler: redirectHandler,
	}
	redirectHandler.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "watch your terminal after closing this tab.")
		redirectChan <- r.URL.Query()
	})
	go redirectServer.ListenAndServe()

	redirectParams := <-redirectChan
	redirectServer.Shutdown(ctx)

	ts, err := authz.Exchange(ctx, redirectParams.Get("code"), redirectParams.Get("state"))
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
