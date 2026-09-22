package conf

import (
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/nowhere"
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
	MixFallback   string   `json:"mixFallback"`
}

func (c *NowhereEndpointConfig) Build() (*nowhere.Endpoint, error) {
	if c == nil || c.Address == nil || c.Address.Address == nil || c.Port == 0 || c.Password == "" {
		return nil, errors.New("nowhere: endpoint requires address, port, and password")
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
	}
	if c.MixFallback != "" {
		fallback, err := time.ParseDuration(c.MixFallback)
		if err != nil {
			return nil, errors.New("nowhere: invalid mixFallback").Base(err)
		}
		if fallback < 0 {
			return nil, errors.New("nowhere: mixFallback must be >= 0")
		}
		endpoint.MixFallbackNs = int64(fallback)
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
		next, err := c.Next.Build()
		if err != nil {
			return nil, err
		}
		config.Next = next
	}
	return config, nil
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
