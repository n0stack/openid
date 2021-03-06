package authenticator

import (
	"crypto/rsa"
	"fmt"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

var _ ClientAuthentication = &OIDCAuthenticator{}

func (a *OIDCAuthenticator) PublicClient(clientID string) Authentication {
	out := a.Clone()

	out.onAuthorizationRequest = append(out.onAuthorizationRequest, func(values url.Values) error {
		values.Add("client_id", clientID)
		return nil
	})
	out.onTokenRequest = append(out.onTokenRequest, func(values url.Values) error {
		values.Add("client_id", clientID)
		return nil
	})

	return out
}

func (a *OIDCAuthenticator) ClientSecret(clientID string, clientSecret string) Authentication {
	out := a.Clone()

	out.onAuthorizationRequest = append(out.onAuthorizationRequest, func(values url.Values) error {
		values.Add("client_id", clientID)
		return nil
	})
	out.onTokenRequest = append(out.onTokenRequest, func(values url.Values) error {
		values.Add("client_id", clientID)
		values.Add("client_secret", clientSecret)
		return nil
	})

	return out
}

const ClientBearerJWTIssuer = "go.n0stack.dev/lib/openid/connect/authenticator"
const ClientBearerJWTExpiration = 3 * time.Minute

func (a *OIDCAuthenticator) ClientBearerJWT(clientID string, privateKey *rsa.PrivateKey) Authentication {
	out := a.Clone()

	out.onAuthorizationRequest = append(out.onAuthorizationRequest, func(values url.Values) error {
		values.Add("client_id", clientID)
		return nil
	})
	out.onTokenRequest = append(out.onTokenRequest, func(values url.Values) error {
		t := jwt.New()
		// commented based on strange Keycloak implementation; keycloak returns error "Client authentication with signed JWT failed: Issuer mismatch. The issuer should match the subject"
		// t.Set(jwt.IssuerKey, ClientBearerJWTIssuer)
		t.Set(jwt.IssuerKey, clientID)
		t.Set(jwt.AudienceKey, out.Config.TokenEndpoint)
		t.Set(jwt.SubjectKey, clientID)
		t.Set(jwt.ExpirationKey, time.Now().Add(ClientBearerJWTExpiration).Unix())
		t.Set(jwt.IssuedAtKey, time.Now().Unix())
		t.Set(jwt.JwtIDKey, randString(32))

		signed, err := jwt.Sign(t, jwa.RS256, privateKey)
		if err != nil {
			return fmt.Errorf(`jwt.Sign(%#v, jwa.RS256, privateKey) %w`, t, err)
		}

		values.Add("client_id", clientID)
		values.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		values.Add("client_assertion", string(signed))

		return nil
	})

	return out
}
