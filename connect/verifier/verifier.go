package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"go.n0stack.dev/lib/openid/configuration"
)

type TokenVerifier struct {
	// Using parameters:
	//   - jwks_url
	//   - issuer
	Config *configuration.OpenIDConfiguration

	keyset jwk.Set
	now    func() time.Time
}

func NewTokenVerifier(ctx context.Context, config *configuration.OpenIDConfiguration) (*TokenVerifier, error) {
	out := &TokenVerifier{
		Config: config,
		now:    time.Now,
	}

	if err := out.RefreshKeyset(ctx); err != nil {
		return nil, fmt.Errorf(`out.RefreshKeyset(ctx) %w`, err)
	}

	return out, nil
}

// RefreshKeyset fetch JWKS from Config.JwksUri
func (verifier *TokenVerifier) RefreshKeyset(ctx context.Context) error {
	keyset, err := jwk.Fetch(ctx, verifier.Config.JwksUri)
	if err != nil {
		return fmt.Errorf(`jwk.Fetch(ctx, "%s") %w`, verifier.Config.JwksUri, err)
	}

	verifier.keyset = keyset
	return nil
}

func (verifier *TokenVerifier) ReadKeyset(buf []byte) error {
	keyset, err := jwk.Parse(buf)
	if err != nil {
		return fmt.Errorf(`jwk.Parse(buf) %w`, err)
	}

	verifier.keyset = keyset
	return nil
}

// TODO: support rotation jwks
// func (verifier *TokenVerifier) BeginAutoRefreshKeyset(ctx context.Context, refreshInterval time.Duration) error {
// 	return nil
// }

func (verifier *TokenVerifier) VerifySign(token []byte, claims ...interface{}) error {
	payload, err := jws.VerifySet(token, verifier.keyset)
	if err != nil {
		return fmt.Errorf(`jws.VerifySet(token, verifier.keyset) %w`, err)
	}

	for _, c := range claims {
		if err := json.Unmarshal(payload, c); err != nil {
			return fmt.Errorf(`json.Unmarshal(payload, c=%#v) %w`, c, err)
		}
	}

	return nil
}

// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
type StandardClaims struct {
	// 4.1.1.  "iss" (Issuer) Claim
	// The "iss" (issuer) claim identifies the principal that issued the JWT.  The processing of this claim is generally application specific.  The "iss" value is a case-sensitive string containing a StringOrURI  value.  Use of this claim is OPTIONAL.
	Issuer string `json:"iss"`

	// 4.1.2.  "sub" (Subject) Claim
	// The "sub" (subject) claim identifies the principal that is the subject of the JWT.  The claims in a JWT are normally statements about the subject.  The subject value MUST either be scoped to be locally unique in the context of the issuer or be globally unique.  The processing of this claim is generally application specific.  The "sub" value is a case-sensitive string containing a StringOrURI value.  Use of this claim is OPTIONAL.
	Subject string `json:"sub"`

	// 4.1.3.  "aud" (Audience) Claim
	// The "aud" (audience) claim identifies the recipients that the JWT is intended for.  Each principal intended to process the JWT MUST identify itself with a value in the audience claim.  If the principal processing the claim does not identify itself with a value in the "aud" claim when this claim is present, then the JWT MUST be rejected.  In the general case, the "aud" value is an array of case-sensitive strings, each containing a StringOrURI value.  In the special case when the JWT has one audience, the "aud" value MAY be a single case-sensitive string containing a StringOrURI value.  The interpretation of audience values is generally application specific.  Use of this claim is OPTIONAL.
	Audience string `json:"aud"`

	// 4.1.4.  "exp" (Expiration Time) Claim
	// The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.  The processing of the "exp" claim requires that the current date/time MUST be before the expiration date/time listed in the "exp" claim.  Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.  Its value MUST be a number containing a NumericDate value.  Use of this claim is OPTIONAL.
	ExpirationTime int64 `json:"exp"`

	// 4.1.5.  "nbf" (Not Before) Claim
	// The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.  The processing of the "nbf" claim requires that the current date/time MUST be after or equal to the not-before date/time listed in the "nbf" claim.  Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.  Its value MUST be a number containing a NumericDate value.  Use of this claim is OPTIONAL.
	NotBefore int64 `json:"nbf"`

	// 4.1.6.  "iat" (Issued At) Claim
	// The "iat" (issued at) claim identifies the time at which the JWT was issued.  This claim can be used to determine the age of the JWT.  Its value MUST be a number containing a NumericDate value.  Use of this claim is OPTIONAL.
	IssuedAt int64 `json:"iat"`

	// 4.1.7.  "jti" (JWT ID) Claim
	// The "jti" (JWT ID) claim provides a unique identifier for the JWT.  The identifier value MUST be assigned in a manner that ensures that there is a negligible probability that the same value will be accidentally assigned to a different data object; if the application uses multiple issuers, collisions MUST be prevented among values produced by different issuers as well.  The "jti" claim can be used to prevent the JWT from being replayed.  The "jti" value is a case-sensitive string.  Use of this claim is OPTIONAL.
	JWTID string `json:"jti"`
}

var (
	ErrorMismatchIssuer   = fmt.Errorf("mismatch issuer")
	ErrorMismatchAudience = fmt.Errorf("mismatch audience")
	ErrorExpired          = fmt.Errorf("token is expired")
	ErrorSillNotActive    = fmt.Errorf("token is still not active")
)

func (t *StandardClaims) CheckIssuer(in string) error {
	if t.Issuer != in {
		return ErrorMismatchIssuer
	}

	return nil
}

func (t *StandardClaims) CheckAudience(in string) error {
	if t.Audience != in {
		return ErrorMismatchAudience
	}

	return nil
}

func (t *StandardClaims) CheckExpirationTime(now time.Time) error {
	if now.After(time.Unix(t.ExpirationTime, 0)) {
		return ErrorExpired
	}

	return nil
}

func (t *StandardClaims) CheckNotBefore(now time.Time) error {
	if now.Before(time.Unix(t.ExpirationTime, 0)) {
		return ErrorSillNotActive
	}

	return nil
}

// http://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#IDTokenValidation
//
// NOT SUPPORTING VALIDATION:
//   4. If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
//   5. If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim Value.
//   6. If the ID Token is received via direct communication between the Client and the Token Endpoint (which it is in this flow), the TLS server validation MAY be used to validate the issuer in place of checking the token signature. The Client MUST validate the signature of all other ID Tokens according to JWS [JWS] using the algorithm specified in the JWT alg Header Parameter. The Client MUST use the keys provided by the Issuer.
//   7. The alg value SHOULD be the default of RS256 or the algorithm sent by the Client in the id_token_signed_response_alg parameter during Registration.
//   8. If the JWT alg Header Parameter uses a MAC based algorithm such as HS256, HS384, or HS512, the octets of the UTF-8 representation of the client_secret corresponding to the client_id contained in the aud (audience) Claim are used as the key to validate the signature. For MAC based algorithms, the behavior is unspecified if the aud is multi-valued or if an azp value is present that is different than the aud value.
//   10. The iat Claim can be used to reject tokens that were issued too far away from the current time, limiting the amount of time that nonces need to be stored to prevent attacks. The acceptable range is Client specific.
//   11. If a nonce value was sent in the Authentication Request, a nonce Claim MUST be present and its value checked to verify that it is the same value as the one that was sent in the Authentication Request. The Client SHOULD check the nonce value for replay attacks. The precise method for detecting replay attacks is Client specific.
//   12. If the acr Claim was requested, the Client SHOULD check that the asserted Claim Value is appropriate. The meaning and processing of acr Claim Values is out of scope for this specification.
//   13. If the auth_time Claim was requested, either through a specific request for this Claim or by using the max_age parameter, the Client SHOULD check the auth_time Claim value and request re-authentication if it determines too much time has elapsed since the last End-User authentication.
func (verifier *TokenVerifier) VerifyIDToken(idToken []byte, clientID string) (*StandardClaims, error) {
	out := &StandardClaims{}

	// 1. If the ID Token is encrypted, decrypt it using the keys and algorithms that the Client specified during Registration that the OP was to use to encrypt the ID Token. If encryption was negotiated with the OP at Registration time and the ID Token is not encrypted, the RP SHOULD reject it.
	if err := verifier.VerifySign(idToken, out); err != nil {
		return nil, fmt.Errorf(`verifier.VerifySign(idToken, out) %w`, err)
	}

	// 2. The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim.
	if err := out.CheckIssuer(verifier.Config.Issuer); err != nil {
		return nil, err
	}

	// 3. The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience. The aud (audience) Claim MAY contain an array with more than one element. The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences not trusted by the Client.
	if err := out.CheckAudience(clientID); err != nil {
		return nil, err
	}

	// 9. The current time MUST be before the time represented by the exp Claim.
	if err := out.CheckExpirationTime(verifier.now()); err != nil {
		return nil, err
	}

	// additional check
	if err := out.CheckNotBefore(verifier.now()); err != nil {
		return nil, err
	}

	return out, nil
}
