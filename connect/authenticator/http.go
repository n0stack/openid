package authenticator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	oidc "go.n0stack.dev/lib/openid/connect"
)

func obtainToken(ctx context.Context, tokenURL string, values url.Values) (*oidc.Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf(`http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(values.Encode())) %w`, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(`http.DefaultClient.Do(req) %w`, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf := &bytes.Buffer{}
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("status code is not 200: got=%d, body=%s", resp.StatusCode, buf.String())
	}

	token := &oidc.Token{}
	if err := json.NewDecoder(resp.Body).Decode(token); err != nil {
		return nil, fmt.Errorf(`json.NewDecoder(resp.Body).Decode(token) %w`, err)
	}

	return token, nil
}
