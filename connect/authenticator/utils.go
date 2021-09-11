package authenticator

import (
	"crypto/rand"
	"encoding/base64"
)

func randString(length int) string {
	r := make([]byte, length)
	rand.Read(r)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(r)[:length]
}
