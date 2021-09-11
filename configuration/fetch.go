package configuration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
const WellKnownOpenidConfigurationPath = "/.well-known/openid-configuration"

func Fetch(ctx context.Context, issuer string) (*OpenIDConfiguration, error) {
	openidConfigurationURL := strings.TrimRight(issuer, "/") + WellKnownOpenidConfigurationPath
	resp, err := http.Get(openidConfigurationURL)
	if err != nil {
		return nil, fmt.Errorf(`http.Get(openidConfigurationURL=%s) %w`, openidConfigurationURL, err)
	}
	defer resp.Body.Close()

	config := &OpenIDConfiguration{}
	if err := json.NewDecoder(resp.Body).Decode(config); err != nil {
		return nil, fmt.Errorf(`json.NewDecoder(resp.Body).Decode(config) %w`, err)
	}

	return config, nil
}
