package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/nowhere"
)

func TestNowhereJSONConfig(t *testing.T) {
	raw := []byte(`{
		"address": "example.com",
		"port": 443,
		"password": "secret",
		"up": "tcp",
		"down": "udp",
		"mux": true,
		"serverName": "example.com",
		"allowInsecure": true
	}`)
	client := new(conf.NowhereClientConfig)
	if err := json.Unmarshal(raw, client); err != nil {
		t.Fatal(err)
	}
	built, err := client.Build()
	if err != nil {
		t.Fatal(err)
	}
	config := built.(*nowhere.ClientConfig)
	if config.Endpoint.GetAddress() != "example.com" || config.Endpoint.GetPort() != 443 {
		t.Fatalf("endpoint = %+v", config.Endpoint)
	}
	if !config.Endpoint.GetMux() || config.Endpoint.GetDown() != "udp" {
		t.Fatalf("policy = up %s down %s mux %v", config.Endpoint.GetUp(), config.Endpoint.GetDown(), config.Endpoint.GetMux())
	}

	serverRaw := []byte(`{"password":"0123456789abcdef0123456789abcdef","networks":["tcp"],"morph":true}`)
	server := new(conf.NowhereServerConfig)
	if err := json.Unmarshal(serverRaw, server); err != nil {
		t.Fatal(err)
	}
	serverBuilt, err := server.Build()
	if err != nil {
		t.Fatal(err)
	}
	if !serverBuilt.(*nowhere.ServerConfig).GetMorph() {
		t.Fatal("expected morph")
	}
}

func TestNowhereJSONConfigRejectsMixCarrier(t *testing.T) {
	raw := []byte(`{"address":"example.com","port":443,"password":"secret","up":"tcp","down":"mix"}`)
	client := new(conf.NowhereClientConfig)
	if err := json.Unmarshal(raw, client); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Build(); err == nil {
		t.Fatal("expected mix carrier rejection")
	}
}

// portalKey is a valid 32-character lowercase-hex Portal shared key.
const portalKey = "0123456789abcdef0123456789abcdef"

func TestNowhereJSONConfigPortalKeyAdmission(t *testing.T) {
	accepted := []string{
		portalKey,               // exactly 32
		portalKey + portalKey,   // exactly 64
		strings.Repeat("a", 33), // odd length inside the 32-64 window
		strings.Repeat("a", 32), // exactly 32
		strings.Repeat("f", 64), // exactly 64
	}
	for _, key := range accepted {
		server := new(conf.NowhereServerConfig)
		if err := json.Unmarshal([]byte(`{"password":"`+key+`"}`), server); err != nil {
			t.Fatal(err)
		}
		if _, err := server.Build(); err != nil {
			t.Fatalf("key %q rejected: %v", key, err)
		}
	}

	rejected := []struct {
		name string
		key  string
	}{
		{"too short", "0123456789abcdef0123456789abcde"}, // 31
		{"too long", strings.Repeat("a", 65)},            // 65
		{"uppercase", strings.Repeat("A", 32)},           // not lowercase hex
		{"non hex", strings.Repeat("g", 32)},             // not hex at all
		{"short client-style secret", "secret"},          // 1-255 byte client key
	}
	for _, tc := range rejected {
		server := new(conf.NowhereServerConfig)
		if err := json.Unmarshal([]byte(`{"password":"`+tc.key+`"}`), server); err != nil {
			t.Fatal(err)
		}
		if _, err := server.Build(); err == nil {
			t.Fatalf("%s: expected portal key rejection", tc.name)
		}
	}
}

func TestNowhereJSONConfigNextHopKeyAdmission(t *testing.T) {
	raw := []byte(`{
		"password":"` + portalKey + `",
		"networks":["tcp"],
		"next":{"address":"example.com","port":443,"password":"secret"}
	}`)
	server := new(conf.NowhereServerConfig)
	if err := json.Unmarshal(raw, server); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Build(); err == nil {
		t.Fatal("expected next-hop key rejection")
	}

	raw = []byte(`{
		"password":"` + portalKey + `",
		"networks":["tcp"],
		"next":{"address":"example.com","port":443,"password":"` + portalKey + `"}
	}`)
	server = new(conf.NowhereServerConfig)
	if err := json.Unmarshal(raw, server); err != nil {
		t.Fatal(err)
	}
	built, err := server.Build()
	if err != nil {
		t.Fatal(err)
	}
	if built.(*nowhere.ServerConfig).GetNext().GetPassword() != portalKey {
		t.Fatal("next hop password mismatch")
	}
}

func TestNowhereJSONConfigClientKeyStaysLenient(t *testing.T) {
	raw := []byte(`{"address":"example.com","port":443,"password":"secret","up":"tcp","down":"tcp"}`)
	client := new(conf.NowhereClientConfig)
	if err := json.Unmarshal(raw, client); err != nil {
		t.Fatal(err)
	}
	built, err := client.Build()
	if err != nil {
		t.Fatalf("client key must stay lenient: %v", err)
	}
	if built.(*nowhere.ClientConfig).GetEndpoint().GetPassword() != "secret" {
		t.Fatal("client password mismatch")
	}
}

func TestNowhereJSONConfigDialPolicy(t *testing.T) {
	cases := []struct {
		name      string
		dial4     string
		dial6     string
		wantError bool
	}{
		{name: "unset"},
		{name: "auto", dial4: "auto", dial6: "auto"},
		{name: "ipv4", dial4: "127.0.0.1"},
		{name: "ipv6", dial6: "::1"},
		{name: "both", dial4: "127.0.0.1", dial6: "::1"},
		{name: "dial4 not ipv4", dial4: "::1", wantError: true},
		{name: "dial6 not ipv6", dial6: "127.0.0.1", wantError: true},
		{name: "dial6 ipv4 mapped", dial6: "::ffff:127.0.0.1", wantError: true},
		{name: "dial4 garbage", dial4: "not-an-ip", wantError: true},
		{name: "dial6 garbage", dial6: "not-an-ip", wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(`{"address":"example.com","port":443,"password":"secret","up":"tcp","down":"tcp"`)
			if tc.dial4 != "" {
				raw = append(raw, []byte(`,"dial4":"`+tc.dial4+`"`)...)
			}
			if tc.dial6 != "" {
				raw = append(raw, []byte(`,"dial6":"`+tc.dial6+`"`)...)
			}
			raw = append(raw, '}')
			client := new(conf.NowhereClientConfig)
			if err := json.Unmarshal(raw, client); err != nil {
				t.Fatal(err)
			}
			_, err := client.Build()
			if tc.wantError {
				if err == nil {
					t.Fatal("expected dial policy rejection")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
		})
	}
}
