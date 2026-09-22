package nowhere

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	stdnet "net"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/nowhere/wire"
)

func loadServerCertificates(list []*Certificate) ([]tls.Certificate, error) {
	if len(list) == 0 {
		cert, err := generateCertificate()
		if err != nil {
			return nil, err
		}
		return []tls.Certificate{cert}, nil
	}
	out := make([]tls.Certificate, 0, len(list))
	for i, item := range list {
		if item == nil || len(item.Certificate) == 0 || len(item.Key) == 0 {
			return nil, errors.New("nowhere: certificate ", i, " is incomplete")
		}
		cert, err := tls.X509KeyPair(item.Certificate, item.Key)
		if err != nil {
			return nil, errors.New("nowhere: failed to parse certificate").Base(err)
		}
		out = append(out, cert)
	}
	return out, nil
}

func generateCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"nowhere.local"},
		IPAddresses:  []stdnet.IP{stdnet.ParseIP("127.0.0.1"), stdnet.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func serverTLSConfig(certs []tls.Certificate, alpn string) *tls.Config {
	return &tls.Config{
		Certificates: certs,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{alpn},
	}
}

func clientTLSConfig(ep *Endpoint, alpn string) (*tls.Config, error) {
	name := ep.ServerName
	if name == "" && stdnet.ParseIP(ep.Address) == nil {
		name = ep.Address
	}
	cfg := &tls.Config{
		ServerName:         name,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{alpn},
		InsecureSkipVerify: ep.AllowInsecure,
	}
	if ep.Pin != "" {
		verify, err := wire.PeerCertificatePinVerifier(ep.Pin)
		if err != nil {
			return nil, err
		}
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = verify
	}
	return cfg, nil
}

func handshakeInfo(state tls.ConnectionState) (wire.TLSHandshakeInfo, error) {
	material, err := state.ExportKeyingMaterial(wire.TLSExporterLabel, wire.EmptyTLSExporterContext(), wire.TLSExporterLen)
	if err != nil {
		return wire.TLSHandshakeInfo{}, err
	}
	if len(material) != wire.TLSExporterLen {
		return wire.TLSHandshakeInfo{}, errors.New("nowhere: invalid TLS exporter length")
	}
	var exporter wire.TLSExporter
	copy(exporter[:], material)
	return wire.TLSHandshakeInfo{
		TLSVersion:     state.Version,
		NegotiatedALPN: state.NegotiatedProtocol,
		Exporter:       exporter,
	}, nil
}
