package main

import (
	"context"
	"fmt"
	"log"

	"go.n0stack.dev/lib/openid/configuration"
	"go.n0stack.dev/lib/openid/connect/authenticator"
	"go.n0stack.dev/lib/openid/examples"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	ctx := context.Background()

	cfg, err := configuration.Fetch(ctx, examples.ExampleIssuer)
	if err != nil {
		log.Fatalf(`configuration.Fetch(ctx, examples.ExampleIssuer) %v`, err)
	}
	cfgout, err := protojson.Marshal(cfg)
	if err != nil {
		log.Fatalf(`protojson.Marshal(cfg) %v`, err)
	}
	log.Printf("Fetched openid configuration %s", cfgout)

	key, err := examples.ParsePrivateKey([]byte(examples.ClientRFC7523PrivateKey))
	if err != nil {
		log.Fatalf(`examples.ParsePrivateKey([]byte(examples.ClientRFC7523PrivateKey)) %v`, err)
	}

	ts := authenticator.Begin(cfg).ClientBearerJWT(examples.ClientRFC7523, key).ClientCredentialsGrant()

	token, err := ts.Token(ctx)
	if err != nil {
		log.Fatalf(`ts.Token(ctx) %v`, err)
	}

	fmt.Printf("Got token %v", token)
}
