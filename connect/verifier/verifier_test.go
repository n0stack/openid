package verifier

import (
	"context"
	"testing"

	"go.n0stack.dev/lib/openid/configuration"
)

// using token of https://openidconnect.net/
func TestVerifyIDToken(t *testing.T) {
	ctx := context.Background()
	issuer := "https://samples.auth0.com/"
	idToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRJRCI6ImtieXVGRGlkTExtMjgwTEl3VkZpYXpPcWpPM3R5OEtIIiwiY3JlYXRlZF9hdCI6IjIwMjEtMDgtMDlUMTE6NDk6NDIuNTQ4WiIsImVtYWlsIjoia2F3YWhhcmFAbmV0LmxhYi51ZWMuYWMuanAiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZmFtaWx5X25hbWUiOiJLYXdhaGFyYSIsImdpdmVuX25hbWUiOiJIaXJva2kiLCJpZGVudGl0aWVzIjpbeyJwcm92aWRlciI6Imdvb2dsZS1vYXV0aDIiLCJ1c2VyX2lkIjoiMTAzMzY4OTMxNzIzOTY4NTA4MTI1IiwiY29ubmVjdGlvbiI6Imdvb2dsZS1vYXV0aDIiLCJpc1NvY2lhbCI6dHJ1ZX1dLCJsb2NhbGUiOiJqYSIsIm5hbWUiOiJIaXJva2kgS2F3YWhhcmEiLCJuaWNrbmFtZSI6Imthd2FoYXJhIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FBVFhBSng0bHNMWmZPWDlXOHU4RmNWNm84UFkyaFdBNndVVmJ3Q29JMTE3PXM5Ni1jIiwidXBkYXRlZF9hdCI6IjIwMjEtMDgtMDlUMTE6NDk6NDIuNTQ4WiIsInVzZXJfaWQiOiJnb29nbGUtb2F1dGgyfDEwMzM2ODkzMTcyMzk2ODUwODEyNSIsInVzZXJfbWV0YWRhdGEiOnt9LCJhcHBfbWV0YWRhdGEiOnt9LCJpc3MiOiJodHRwczovL3NhbXBsZXMuYXV0aDAuY29tLyIsInN1YiI6Imdvb2dsZS1vYXV0aDJ8MTAzMzY4OTMxNzIzOTY4NTA4MTI1IiwiYXVkIjoia2J5dUZEaWRMTG0yODBMSXdWRmlhek9xak8zdHk4S0giLCJpYXQiOjE2Mjg1MDk3ODgsImV4cCI6MTYyODU0NTc4OH0.-1AruoDAo21juc-fqjF3EraVy1zIU-JqAF-sWQz6F6c"
	clientID := "kbyuFDidLLm280LIwVFiazOqjO3ty8KH"

	config, err := configuration.Fetch(ctx, issuer)
	if err != nil {
		t.Errorf("%v", err)
	}

	verifier, err := NewTokenVerifier(ctx, config)
	if err != nil {
		t.Errorf("%v", err)
	}

	claims, err := verifier.VerifyIDToken([]byte(idToken), clientID)
	if err != nil {
		t.Errorf("%v", err)
	}

	t.Errorf("%v", claims)
}
