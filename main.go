package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os/exec"
	"time"
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

func main() {
	client := &http.Client{Timeout: 1000 * time.Millisecond}
	// Do this every minute
	// ctx, cancel := context.WithTimeout(context.Background(), 5000*time.Millisecond)
	// defer cancel()

	for {
		// cmd := `curl localhost:15000/config_dump | jq '.configs[] | select(."@type"=="type.googleapis.com/envoy.admin.v3.ListenersConfigDump") | .dynamic_listeners[] | .active_state.listener.filter_chains[] | .filters[] | .typed_config.http_filters[] | select(.name=="envoy.filters.http.jwt_authn") | .typed_config.providers '`
		cmd := `curl localhost:15000/config_dump | jq '.configs[] | select(."@type"=="type.googleapis.com/envoy.admin.v3.ListenersConfigDump") | .dynamic_listeners[] | .. | .providers? // empty'`
		out, err := exec.Command("sh", "-c", cmd).Output()
		if err != nil {
			log.Println("Error curling for config_dump")
			log.Println(err.Error())
		}

		jwk_providers := map[string]provider{}
		err = json.Unmarshal(out, &jwk_providers)
		if err != nil {
			log.Println("Error unmarshalling curled objects")
		}

		// Compare every issuer's local key id to what the issuer show
		check_diff(client, jwk_providers)
		time.Sleep(1 * time.Minute)
	}
}

// check_diff compare every local jwk key with the current provider key
func check_diff(c *http.Client, local_providers map[string]provider) {
	for _, lp := range local_providers {
		// provider key uri
		uri, ok := keys_uri[lp.Issuer]
		if !ok {
			log.Println("Issuer not coded for")
		}

		remote_keys, err := get_keys(c, uri)
		if err != nil {
			log.Println("Error getting remote keys for", uri)
		}

		local_keys, err := convert_lp_key(lp)
		if err != nil {
			log.Println("Error converting local inline string to key")
		}

		log.Println("Comparing", lp.Issuer)
		mismatch := compare(lp, local_keys, remote_keys)
		if len(mismatch) != 0 {
			log.Println(mismatch)
		} else {
			log.Println("No mismatch")
		}
	}
}

// compare verify every remote key is stored locally
// if not, prints the remote key that is not stored locally
func compare(lp provider, local_keys []key, remote_keys []key) []string {
	result := []string{}
	for _, rk := range remote_keys {
		if !contains(local_keys, rk) {
			log.Println("ALERT! Remote key not found locally", lp.Issuer, rk, local_keys)
			result = append(result, lp.Issuer, rk.Kid)
		}
	}
	return result
}

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
