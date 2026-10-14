package nowhere

import (
	"context"
	"crypto/tls"
	stdnet "net"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/nowhere/core/morph"
	"github.com/xtls/xray-core/proxy/nowhere/core/portal"
	"github.com/xtls/xray-core/proxy/nowhere/core/wire"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// ServerV3 is the Nowhere 3 Portal. It serves one carrier with ALPN nw3 and
// TLS 1.3, applies the Nowhere 3 Morph transform when enabled, and either
// routes authenticated flows through the Xray dispatcher or bridges them to a
// single registered Egress exit (egress mode). The TCP carrier is fed by Xray's
// listener through Process; the QUIC carrier listens on the same address
// because Nowhere datagrams cannot be demuxed per source.
type ServerV3 struct {
	config    *ServerConfig
	ctx       context.Context
	portal    *portal.Server
	tlsConfig *tls.Config
	carrier   string
	morph     bool
	sharedKey string
	userLevel uint32

	listenAddr xnet.Address
	listenPort xnet.Port
	sockopt    *internet.SocketConfig

	tcpConns chan stdnet.Conn

	closing   chan struct{}
	closeOnce sync.Once
	closeErr  error

	started    bool
	packetConn stdnet.PacketConn
}

// NewServerV3 builds the Nowhere 3 Portal inbound. The nw2 inbound keeps its
// own constructor; NewServer dispatches between the two.
func NewServerV3(ctx context.Context, config *ServerConfig) (*ServerV3, error) {
	version, err := resolveNowhereVersion(config.GetVersion())
	if err != nil {
		return nil, err
	}
	if version != nowhereVersion3 {
		return nil, errors.New("nowhere: version 3 constructor called with version ", version)
	}
	if config.GetPassword() == "" {
		return nil, errors.New("nowhere: missing password")
	}
	if err := validateNowhereV3Server(config); err != nil {
		return nil, err
	}
	carrier, err := nowhereV3Carrier(config.GetCarrier())
	if err != nil {
		return nil, err
	}
	if err := validateNowhereV3Networks(config.GetNetworks(), carrier); err != nil {
		return nil, err
	}
	// The Egress registration handshake only exists on the QUIC carrier, so an
	// exit bridge cannot be served over the TCP carrier.
	if config.GetEgress() && carrier != nowhereV3CarrierQUIC {
		return nil, errors.New("nowhere: version 3 egress mode requires the quic carrier")
	}
	if err := wire.ValidateServiceKey(config.GetPassword()); err != nil {
		return nil, errors.New("nowhere: portal key").Base(err)
	}
	stream, err := validateRawStream(ctx)
	if err != nil {
		return nil, err
	}
	certs, err := loadServerCertificates(config.GetCertificates())
	if err != nil {
		return nil, err
	}
	tlsConfig := buildNowhereV3ServerTLS(certs)
	morphOn := resolveNowhereMorph(config.Morph, nowhereVersion3)
	var upstream portal.Upstream
	if !config.GetEgress() {
		v := core.MustFromContext(ctx)
		var sniff session.SniffingRequest
		if content := session.ContentFromContext(ctx); content != nil {
			sniff = content.SniffingRequest
		}
		tag := ""
		if inbound := session.InboundFromContext(ctx); inbound != nil {
			tag = inbound.Tag
		}
		raw := v.GetFeature(routing.DispatcherType())
		dispatcher, _ := raw.(routing.Dispatcher)
		if dispatcher == nil {
			return nil, errors.New("nowhere: dispatcher is not available")
		}
		upstream = &nw3Upstream{dispatcher: dispatcher, tag: tag, level: config.GetUserLevel(), sniff: sniff}
	}
	portalServer, err := portal.New(portal.Config{
		SharedKey: config.GetPassword(),
		Morph:     morphOn,
		TLS:       tlsConfig,
		Upstream:  upstream,
		Egress:    config.GetEgress(),
	})
	if err != nil {
		return nil, err
	}

	s := &ServerV3{
		config:    config,
		ctx:       ctx,
		portal:    portalServer,
		tlsConfig: tlsConfig,
		carrier:   carrier,
		morph:     morphOn,
		sharedKey: config.GetPassword(),
		userLevel: config.GetUserLevel(),
		tcpConns:  make(chan stdnet.Conn, 64),
		closing:   make(chan struct{}),
	}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		if inbound.Source.Address != nil {
			s.listenAddr = inbound.Source.Address
		}
		s.listenPort = inbound.Source.Port
	}
	if stream != nil {
		s.sockopt = stream.SocketSettings
	}
	return s, nil
}

func (s *ServerV3) Network() []xnet.Network {
	if s.carrier == nowhereV3CarrierTCP {
		return []xnet.Network{xnet.Network_TCP}
	}
	// The QUIC carrier owns its own UDP socket, so Xray registers no worker.
	return nil
}

func (s *ServerV3) Process(ctx context.Context, network xnet.Network, conn stat.Connection, _ routing.Dispatcher) error {
	if network != xnet.Network_TCP || s.carrier != nowhereV3CarrierTCP {
		return errors.New("nowhere: tcp carrier is not enabled")
	}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inbound.Name = "nowhere"
		inbound.CanSpliceCopy = 3
		if inbound.User == nil {
			inbound.User = &protocol.MemoryUser{Level: s.userLevel}
		}
	}
	// The vendored Portal applies the TCP Morph transform itself; handing it an
	// already-wrapped socket would seal the prelude twice.
	watched := &closeSignalConn{Conn: conn, done: make(chan struct{})}
	select {
	case s.tcpConns <- watched:
	case <-s.closing:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
	// The vendored Portal owns the socket once it accepted it; block until the
	// protocol closes it so the TCP worker does not tear the carrier down early.
	select {
	case <-watched.done:
	case <-s.closing:
	case <-ctx.Done():
	}
	return nil
}

func (s *ServerV3) Start() error {
	select {
	case <-s.closing:
		return stdnet.ErrClosed
	default:
	}
	if s.started {
		return nil
	}
	s.started = true
	logNowhereV3PortalFingerprint(core.ToBackgroundDetachedContext(s.ctx), s.tlsConfig)
	if s.carrier == nowhereV3CarrierTCP {
		go func() {
			_ = s.portal.Serve(s.ctx, &pushedListener{addr: s.tcpListenAddr(), conns: s.tcpConns, closed: s.closing})
		}()
		return nil
	}
	if s.listenPort == 0 {
		return errors.New("nowhere: quic carrier requires an inbound listen port")
	}
	packetConn, err := udpCarrierSocket(core.ToBackgroundDetachedContext(s.ctx), udpListenAddr(s.listenAddr, s.listenPort), s.sockopt)
	if err != nil {
		return errors.New("nowhere: failed to listen QUIC").Base(err)
	}
	var keys *morph.Keys
	if s.morph {
		derived := nowhereV3MorphKeys(s.sharedKey)
		keys = &derived
	}
	quicListener, err := listenNowhereV3QUIC(core.ToBackgroundDetachedContext(s.ctx), packetConn, s.tlsConfig, keys)
	if err != nil {
		_ = packetConn.Close()
		return errors.New("nowhere: failed to listen QUIC").Base(err)
	}
	s.packetConn = packetConn
	go func() {
		_ = s.portal.ServeQUIC(s.ctx, quicListener)
	}()
	return nil
}

func (s *ServerV3) Close() error {
	s.closeOnce.Do(func() {
		close(s.closing)
		var errs []error
		if s.packetConn != nil {
			errs = append(errs, s.packetConn.Close())
		}
		s.closeErr = errors.Combine(errs...)
	})
	return s.closeErr
}

func (s *ServerV3) tcpListenAddr() stdnet.Addr {
	ip := stdnet.IPv4zero
	if s.listenAddr != nil && s.listenAddr.Family().IsIP() {
		ip = s.listenAddr.IP()
	}
	return &stdnet.TCPAddr{IP: ip, Port: int(s.listenPort)}
}

// pushedListener is the net.Listener view of the TCP carrier: connections Xray
// accepted are queued by Process and drained by the vendored Portal.
type pushedListener struct {
	addr   stdnet.Addr
	conns  chan stdnet.Conn
	closed chan struct{}
}

func (l *pushedListener) Accept() (stdnet.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, stdnet.ErrClosed
	}
}

// Close is a no-op: the queued connections belong to Xray's TCP workers, which
// close them through the inbound handler's own lifecycle.
func (l *pushedListener) Close() error { return nil }

func (l *pushedListener) Addr() stdnet.Addr { return l.addr }

var (
	_ proxy.Inbound   = (*ServerV3)(nil)
	_ common.Runnable = (*ServerV3)(nil)
	_ common.Closable = (*ServerV3)(nil)
	_ stdnet.Listener = (*pushedListener)(nil)
)
