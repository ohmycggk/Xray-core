package conf_test

import (
	"encoding/json"
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
		"down": "mix",
		"mux": true,
		"serverName": "example.com",
		"allowInsecure": true,
		"mixFallback": "1500ms"
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
	if !config.Endpoint.GetMux() || config.Endpoint.GetDown() != "mix" {
		t.Fatalf("policy = up %s down %s mux %v", config.Endpoint.GetUp(), config.Endpoint.GetDown(), config.Endpoint.GetMux())
	}
	if config.Endpoint.GetMixFallbackNs() != int64(1500*1000000) {
		t.Fatalf("mix fallback = %d", config.Endpoint.GetMixFallbackNs())
	}

	serverRaw := []byte(`{"password":"secret","networks":["tcp"],"morph":true}`)
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
