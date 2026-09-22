package nowhere

import (
	"context"
	"crypto/tls"
	stdnet "net"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/nowhere/bundle"
	"github.com/xtls/xray-core/proxy/nowhere/carrier/tcptls"
	"github.com/xtls/xray-core/proxy/nowhere/wire"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func validateRawStream(ctx context.Context) (*internet.MemoryStreamConfig, error) {
	raw := session.StreamSettingsFromContext(ctx)
	if raw == nil {
		return nil, nil
	}
	mss, ok := raw.(*internet.MemoryStreamConfig)
	if !ok || mss == nil {
		return nil, nil
	}
	if mss.ProtocolName != "" && mss.ProtocolName != "tcp" {
		return nil, errors.New("nowhere requires raw TCP; set streamSettings.network to tcp, got ", mss.ProtocolName)
	}
	if mss.SecurityType != "" && mss.SecurityType != "none" {
		return nil, errors.New("nowhere performs its own TLS; set streamSettings.security to none")
	}
	return mss, nil
}

func normalizeMode(value string) (bundle.CarrierMode, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = "tcp"
	}
	return bundle.ParseCarrierMode(value)
}

func (e *Endpoint) validate() error {
	if e == nil || e.Address == "" || e.Port == 0 || e.Port > 65535 || e.Password == "" {
		return errors.New("nowhere: endpoint requires address, port, and password")
	}
	if e.Pool < 0 {
		return errors.New("nowhere: pool must be >= 0")
	}
	if e.MixFallbackNs < 0 {
		return errors.New("nowhere: mix fallback must be >= 0")
	}
	if _, err := normalizeMode(e.Up); err != nil {
		return err
	}
	if _, err := normalizeMode(e.Down); err != nil {
		return err
	}
	return nil
}

func (e *Endpoint) hostport() string {
	return stdnet.JoinHostPort(e.Address, strconv.FormatUint(uint64(e.Port), 10))
}

type carrierDialer interface {
	DialTCP(ctx context.Context, address string) (stdnet.Conn, error)
	DialPacket(ctx context.Context, address string) (stdnet.PacketConn, stdnet.Addr, error)
}

type xrayDialer struct {
	dialer  internet.Dialer
	sockopt *internet.SocketConfig
	system  bool
}

func (d xrayDialer) DialTCP(ctx context.Context, address string) (stdnet.Conn, error) {
	dest, err := xnet.ParseDestination("tcp:" + address)
	if err != nil {
		return nil, err
	}
	if d.system || d.dialer == nil {
		return internet.DialSystem(ctx, dest, d.sockopt)
	}
	return d.dialer.Dial(ctx, dest)
}

func (d xrayDialer) DialPacket(ctx context.Context, address string) (stdnet.PacketConn, stdnet.Addr, error) {
	dest, err := xnet.ParseDestination("udp:" + address)
	if err != nil {
		return nil, nil, err
	}
	var conn stdnet.Conn
	if d.system || d.dialer == nil {
		conn, err = internet.DialSystem(ctx, dest, d.sockopt)
	} else {
		conn, err = d.dialer.Dial(ctx, dest)
	}
	if err != nil {
		return nil, nil, err
	}
	pc, addr, uerr := unwrapPacketConn(conn)
	if uerr != nil {
		_ = conn.Close()
		return nil, nil, uerr
	}
	return pc, addr, nil
}

func unwrapPacketConn(conn stdnet.Conn) (stdnet.PacketConn, stdnet.Addr, error) {
	conn = stat.TryUnwrapStatsConn(conn)
	switch c := conn.(type) {
	case *internet.PacketConnWrapper:
		return c.PacketConn, c.Dest, nil
	case *finalmask.PacketConnWrapper:
		return c.PacketConn, c.RemoteAddr(), nil
	default:
		if pc, ok := conn.(stdnet.PacketConn); ok {
			return pc, conn.RemoteAddr(), nil
		}
		return nil, nil, errors.New("nowhere: UDP dial did not return a packet connection")
	}
}

type tlsClientDialer struct {
	config *tls.Config
}

func (d tlsClientDialer) DialTLSConn(ctx context.Context, raw stdnet.Conn) (wire.HandshakedConn, error) {
	conn := tls.Client(raw, d.config.Clone())
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return wire.HandshakedConn{}, err
	}
	info, err := handshakeInfo(conn.ConnectionState())
	if err != nil {
		_ = conn.Close()
		return wire.HandshakedConn{}, err
	}
	return wire.HandshakedConn{Conn: conn, TLSHandshakeInfo: info}, nil
}

func openBundle(ep *Endpoint, dial carrierDialer) (*bundle.CarrierBundle, error) {
	if err := ep.validate(); err != nil {
		return nil, err
	}
	up, err := normalizeMode(ep.Up)
	if err != nil {
		return nil, err
	}
	down, err := normalizeMode(ep.Down)
	if err != nil {
		return nil, err
	}
	alpn, err := wire.NormalizeALPN(ep.Alpn)
	if err != nil {
		return nil, err
	}
	credentials, err := wire.NewCredentials(ep.Password)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := clientTLSConfig(ep, alpn)
	if err != nil {
		return nil, err
	}
	needsTCP := up != bundle.ModeUDP || down != bundle.ModeUDP
	needsQUIC := up != bundle.ModeTCP || down != bundle.ModeTCP
	muxMode := bundle.MuxDisabled
	if ep.Mux {
		muxMode = bundle.MuxEnabled
	}
	if (needsQUIC || muxMode == bundle.MuxEnabled) && ep.Pool != 0 {
		return nil, errors.New("nowhere: pool must be 0 when mux or QUIC is enabled")
	}
	upCarrier, mixUp := up.Selectors()
	downCarrier, mixDown := down.Selectors()
	addr := ep.hostport()
	opts := bundle.BundleOptions{
		Credentials:        credentials,
		ALPN:               alpn,
		PoolSize:           int(ep.Pool),
		Up:                 upCarrier,
		Down:               downCarrier,
		MixUp:              mixUp,
		MixDown:            mixDown,
		MixFallbackTimeout: time.Duration(ep.MixFallbackNs),
		Mux:                muxMode,
	}
	var morphKey []byte
	if ep.Morph {
		morphKey = []byte(ep.Password)
	}
	if needsTCP {
		cfg, err := tcptls.NewConfig(tcptls.TCPOptions{
			Address:        addr,
			Dialer:         tcpDialFunc(func(ctx context.Context, _, address string) (stdnet.Conn, error) { return dial.DialTCP(ctx, address) }),
			TLSDialer:      tlsClientDialer{config: tlsConfig},
			MorphSharedKey: morphKey,
		})
		if err != nil {
			return nil, err
		}
		opts.TCP = cfg
	}
	if needsQUIC {
		var keys *morphKeys
		if ep.Morph {
			derived := deriveMorph(ep.Password)
			keys = &derived
		}
		opts.QUIC = newQUICBackend(func(ctx context.Context) (stdnet.PacketConn, stdnet.Addr, error) {
			return dial.DialPacket(ctx, addr)
		}, tlsConfig, quicSettings(false, ep.Morph), keys)
	}
	return bundle.NewCarrierBundle(opts)
}

type tcpDialFunc func(ctx context.Context, network, address string) (stdnet.Conn, error)

func (f tcpDialFunc) DialContext(ctx context.Context, network, address string) (stdnet.Conn, error) {
	return f(ctx, network, address)
}
