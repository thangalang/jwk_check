package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"time"

	"github.com/blendle/zapdriver"
	"go.uber.org/zap"
)

type key struct {
	Kid string
	Kty string
	Use string
	Alg string
	N   string
	E   string
}

type local_jwk struct {
	Inline_string string
}
type provider struct {
	Issuer              string
	Local_jwks          local_jwk
	Forward             bool
	Payload_in_metadata string
}

var keys_uri = map[string]string{
	"https://accounts.google.com":                          "https://www.googleapis.com/oauth2/v3/certs",
	"https://my.dev.wpesvc.net/capi/v1/":                   "https://my.dev.wpesvc.net/capi/private/.well-known/keys",
	"https://mystaging.wpengine.com/capi/v1/":              "https://mystaging.wpengine.com/capi/private/.well-known/keys",
	"https://my.wpengine.com/capi/v1/":                     "https://my.wpengine.com/capi/private/.well-known/keys",
	"https://identity-dev.wpengine.com/oauth2/default":     "https://identity-dev.wpengine.com/oauth2/default/v1/keys",
	"https://identity-staging.wpengine.com/oauth2/default": "https://identity-staging.wpengine.com/oauth2/default/v1/keys",
	"https://identity.wpengine.com/oauth2/default":         "https://identity.wpengine.com/oauth2/default/v1/keys",
}

var last_used_keys = map[string][]key{
	"https://accounts.google.com":                          {},
	"https://my.dev.wpesvc.net/capi/v1/":                   {},
	"https://mystaging.wpengine.com/capi/v1/":              {},
	"https://my.wpengine.com/capi/v1/":                     {},
	"https://identity-dev.wpengine.com/oauth2/default":     {},
	"https://identity-staging.wpengine.com/oauth2/default": {},
	"https://identity.wpengine.com/oauth2/default":         {},
}

func main() {
	client := &http.Client{Timeout: 1000 * time.Millisecond}
	logger, err := zapdriver.NewProduction()
	if err != nil {
		log.Println(err.Error)
	}
	for {
		// cmd := `curl localhost:15000/config_dump | jq '.configs[] | select(."@type"=="type.googleapis.com/envoy.admin.v3.ListenersConfigDump") | .dynamic_listeners[] | .active_state.listener.filter_chains[] | .filters[] | .typed_config.http_filters[] | select(.name=="envoy.filters.http.jwt_authn") | .typed_config.providers '`
		cmd := `curl localhost:15000/config_dump | jq '.configs[] | select(."@type"=="type.googleapis.com/envoy.admin.v3.ListenersConfigDump") | .dynamic_listeners[] | .. | .providers? // empty'`
		out, err := exec.Command("sh", "-c", cmd).Output()
		if err != nil {
			logger.Error("Error curling for config_dump")
			logger.Error(err.Error())
		}

		jwk_providers := map[string]provider{}
		err = json.Unmarshal(out, &jwk_providers)
		if err != nil {
			logger.Error("Error unmarshalling curled objects")
			logger.Error(err.Error())
		}

		// Compare every issuer's local key id to what the issuer show
		check_diff(logger, client, jwk_providers)
		time.Sleep(1 * time.Minute)
	}
}

// check_diff compare every local jwk key with the current provider key
func check_diff(logger *zap.Logger, c *http.Client, local_providers map[string]provider) {
	for _, lp := range local_providers {
		// provider key uri
		uri, ok := keys_uri[lp.Issuer]
		if !ok {
			logger.Info("Issuer not coded for",
				zapdriver.Labels(
					zapdriver.Label("Issuer", lp.Issuer),
				),
			)
		}

		remote_keys, err := get_keys(c, uri)
		if err != nil {
			logger.Error("Error getting remote keys for",
				zapdriver.Labels(
					zapdriver.Label("Key", uri),
				),
			)
		}

		local_keys, err := convert_lp_key(lp)
		if err != nil {
			logger.Error("Error converting local inline string to key", zapdriver.Labels(
				zapdriver.Label("Issuer", lp.Issuer),
			))
		}

		logger.Info(fmt.Sprintf("Comparing keys for %v", lp.Issuer), zapdriver.Labels(
			zapdriver.Label("Issuer", lp.Issuer),
			zapdriver.Label("Local Keys", fmt.Sprintf("%v", get_key_ids(local_keys))),
			zapdriver.Label("Remote Keys", fmt.Sprintf("%v", get_key_ids(remote_keys))),
		))

		mismatch := compare(logger, lp, local_keys, remote_keys)
		if len(mismatch) != 0 {
			logger.Error(fmt.Sprintf("Mismatch of keys for issuer %v", lp.Issuer),
				zapdriver.Labels(
					zapdriver.Label("Issuer", lp.Issuer),
					zapdriver.Label("Local Keys", fmt.Sprintf("%v", get_key_ids(local_keys))),
					zapdriver.Label("Remote Keys", fmt.Sprintf("%v", get_key_ids(remote_keys))),
				),
			)
		}

		rotated := is_key_rotated(logger, lp.Issuer, remote_keys)
		if err != nil {
			logger.Error("Error check is key rotated")
			logger.Error(err.Error())
		}

		if rotated {
			logger.Info(fmt.Sprintf("Key rotated %v", lp.Issuer), zapdriver.Labels(
				zapdriver.Label("Issuer", lp.Issuer),
			))
		}
	}
}

func is_key_rotated(logger *zap.Logger, issuer string, remote_keys []key) bool {
	for _, k := range remote_keys {
		if !contains(last_used_keys[issuer], k) {
			// log difference in case thats needed
			logger.Info(fmt.Sprintf("Public Key Rotated %v", issuer), zapdriver.Labels(
				zapdriver.Label("Issuer", issuer),
				zapdriver.Label("Current Remote Keys", fmt.Sprintf("%v", get_key_ids(remote_keys))),
				zapdriver.Label("Last Known Remote Keys", fmt.Sprintf("%v", get_key_ids(last_used_keys[issuer]))),
			))
			// update last used keys to remote_keys
			last_used_keys[issuer] = remote_keys
			return true
		}
	}
	return false
}

func get_key_ids(keys []key) string {
	result := ""
	for _, k := range keys {
		result = result + fmt.Sprintf("|kid: %v ", k.Kid)
	}
	return result
}

// compare verify every remote key is stored locally
// if not, prints the remote key that is not stored locally
func compare(logger *zap.Logger, lp provider, local_keys []key, remote_keys []key) []string {
	result := []string{}

	for _, rk := range remote_keys {
		if !contains(local_keys, rk) {
			logger.Error("ALERT! Remote key not found locally", zapdriver.Labels(
				zapdriver.Label("Issuer", lp.Issuer),
				zapdriver.Label("Remote Key ID", rk.Kid),
				zapdriver.Label("Local Keys", fmt.Sprintf("%v", get_key_ids(local_keys))),
			))
			result = append(result, lp.Issuer, rk.Kid)
		}
	}
	return result
}

// func logLocalKeys(logger *zap.Logger, keys []key) zapcore.Field {
// 	zdl := []zapcore.Field{}
// 	for _, k := range keys {
// 		zdl = append(zdl, zapdriver.Label("Local Key ID", k.Kid))
// 	}
// 	return zapdriver.Labels(zdl...)
// }

// contains check if string is in list of string
func contains(localKeys []key, remoteKey key) bool {
	for _, lk := range localKeys {
		if remoteKey.Kid == lk.Kid {
			// remote key found
			return true
		}
	}
	// not found
	return false
}

// convert_lp_key unmarshal the inline string to a list of keys
func convert_lp_key(lp provider) ([]key, error) {
	m := map[string][]key{}
	err := json.Unmarshal([]byte(lp.Local_jwks.Inline_string), &m)
	if err != nil {
		return []key{}, err
	}
	return m["keys"], nil
}

// get_keys get the shared key from issuer
func get_keys(c *http.Client, uri string) ([]key, error) {
	r, err := c.Get(uri)
	if err != nil {
		return []key{}, err
	}
	defer r.Body.Close()

	m := map[string][]key{}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return []key{}, err
	}
	err = json.Unmarshal(b, &m)
	if err != nil {
		return []key{}, err
	}
	return m["keys"], nil
}
