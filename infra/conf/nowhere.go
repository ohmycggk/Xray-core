package conf

import (
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/nowhere"
	"github.com/xtls/xray-core/proxy/nowhere/bundle"
	"google.golang.org/protobuf/proto"
)

type NowhereEndpointConfig struct {
	Address       *Address `json:"address"`
	Port          uint16   `json:"port"`
	Password      string   `json:"password"`
	Up            string   `json:"up"`
	Down          string   `json:"down"`
	Mux           bool     `json:"mux"`
	Morph         bool     `json:"morph"`
	ServerName    string   `json:"serverName"`
	Pin           string   `json:"pin"`
	AllowInsecure bool     `json:"allowInsecure"`
	Pool          int32    `json:"pool"`
	ALPN          string   `json:"alpn"`
	Dial4         string   `json:"dial4"`
	Dial6         string   `json:"dial6"`
}

func (c *NowhereEndpointConfig) Build() (*nowhere.Endpoint, error) {
	if c == nil || c.Address == nil || c.Address.Address == nil || c.Port == 0 || c.Password == "" {
		return nil, errors.New("nowhere: endpoint requires address, port, and password")
	}
	for _, mode := range []string{c.Up, c.Down} {
		normalized := strings.ToLower(strings.TrimSpace(mode))
		if normalized == "" {
			continue
		}
		if _, err := bundle.ParseCarrierMode(normalized); err != nil {
			return nil, err
		}
	}
	if _, err := nowhere.ParseDialPolicy(c.Dial4, c.Dial6); err != nil {
		return nil, err
	}
	endpoint := &nowhere.Endpoint{
		Address:       c.Address.String(),
		Port:          uint32(c.Port),
		Password:      c.Password,
		Up:            c.Up,
		Down:          c.Down,
		Mux:           c.Mux,
		Morph:         c.Morph,
		ServerName:    c.ServerName,
		Pin:           c.Pin,
		AllowInsecure: c.AllowInsecure,
		Pool:          c.Pool,
		Alpn:          c.ALPN,
		Dial4:         c.Dial4,
		Dial6:         c.Dial6,
	}
	return endpoint, nil
}

type NowhereServerConfig struct {
	Password     string                 `json:"password"`
	Networks     []string               `json:"networks"`
	Morph        bool                   `json:"morph"`
	Certificates []*TLSCertConfig       `json:"certificates"`
	ALPN         string                 `json:"alpn"`
	Next         *NowhereEndpointConfig `json:"next"`
	UserLevel    uint32                 `json:"userLevel"`
}

func (c *NowhereServerConfig) Build() (proto.Message, error) {
	if c == nil || c.Password == "" {
		return nil, errors.New("nowhere: missing password")
	}
	if err := validatePortalKey("Portal listener", c.Password); err != nil {
		return nil, err
	}
	config := &nowhere.ServerConfig{
		Password:  c.Password,
		Networks:  append([]string(nil), c.Networks...),
		Morph:     c.Morph,
		Alpn:      c.ALPN,
		UserLevel: c.UserLevel,
	}
	for _, cert := range c.Certificates {
		built, err := cert.Build()
		if err != nil {
			return nil, errors.New("nowhere: invalid certificate").Base(err)
		}
		config.Certificates = append(config.Certificates, &nowhere.Certificate{
			Certificate: built.Certificate,
			Key:         built.Key,
		})
	}
	if c.Next != nil {
		if err := validatePortalKey("Portal next endpoint", c.Next.Password); err != nil {
			return nil, err
		}
		next, err := c.Next.Build()
		if err != nil {
			return nil, err
		}
		config.Next = next
	}
	return config, nil
}

// Portal key admission bounds: the Nowhere 2.2 Portal shared key is 32-64
// lowercase hexadecimal characters after URL percent-decoding. Odd lengths are
// allowed; the bytes are used directly without hex decoding.
const (
	portalKeyMinLen = 32
	portalKeyMaxLen = 64
)

// validatePortalKey enforces the Portal shared-key rule. JSON configuration
// already carries the percent-decoded value, so no second decoding is applied.
// Client-side keys stay lenient (1-255 decoded bytes) and are bounded by
// wire.NewCredentials instead.
func validatePortalKey(context, key string) error {
	if len(key) < portalKeyMinLen || len(key) > portalKeyMaxLen {
		return errors.New("nowhere: ", context, ": shared key must be 32-64 lowercase hexadecimal characters; use nowhere generate-key")
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errors.New("nowhere: ", context, ": shared key must be 32-64 lowercase hexadecimal characters; use nowhere generate-key")
		}
	}
	return nil
}

type NowhereClientConfig struct {
	NowhereEndpointConfig
	UserLevel uint32 `json:"userLevel"`
}

func (c *NowhereClientConfig) Build() (proto.Message, error) {
	endpoint, err := c.NowhereEndpointConfig.Build()
	if err != nil {
		return nil, err
	}
	return &nowhere.ClientConfig{Endpoint: endpoint, UserLevel: c.UserLevel}, nil
}
