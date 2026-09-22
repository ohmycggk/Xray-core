package nowhere

import (
	"context"
	"crypto/tls"
	stdnet "net"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/nowhere/bundle"
	"github.com/xtls/xray-core/proxy/nowhere/carrier/morph"
	nwserver "github.com/xtls/xray-core/proxy/nowhere/server"
	"github.com/xtls/xray-core/proxy/nowhere/wire"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Server is a Nowhere inbound. TCP is accepted by Xray's listener; QUIC listens
// on the same address because Nowhere datagrams cannot be demuxed per source.
type Server struct {
	config     *ServerConfig
	handler    *nwserver.Handler
	tlsConfig  *tls.Config
	morph      *morph.Keys
	enableTCP  bool
	enableUDP  bool
	userLevel  uint32
	listenAddr xnet.Address
	listenPort xnet.Port
	sockopt    *internet.SocketConfig
	quic       *quicHub
	nextBundle *bundle.CarrierBundle

	closing   chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	if config == nil || config.Password == "" {
		return nil, errors.New("nowhere: missing password")
	}
	stream, err := validateRawStream(ctx)
	if err != nil {
		return nil, err
	}
	tcpOn, udpOn, err := parseNetworks(config.Networks)
	if err != nil {
		return nil, err
	}
	alpn, err := wire.NormalizeALPN(config.Alpn)
	if err != nil {
		return nil, err
	}
	credentials, err := wire.NewCredentials(config.Password)
	if err != nil {
		return nil, err
	}
	var morphKey []byte
	var keys *morph.Keys
	if config.Morph {
		derived := deriveMorph(config.Password)
		keys = &derived
		morphKey = []byte(config.Password)
	}
	networks := make([]nwserver.Network, 0, 2)
	if tcpOn {
		networks = append(networks, nwserver.NetworkTCP)
	}
	if udpOn {
		networks = append(networks, nwserver.NetworkUDP)
	}
	serverConfig, err := nwserver.NewConfig(nwserver.ConfigOptions{
		Credentials:    credentials,
		ALPN:           alpn,
		Networks:       networks,
		MorphSharedKey: morphKey,
	})
	if err != nil {
		return nil, err
	}
	certs, err := loadServerCertificates(config.Certificates)
	if err != nil {
		return nil, err
	}

	v := core.MustFromContext(ctx)
	var sniff session.SniffingRequest
	if content := session.ContentFromContext(ctx); content != nil {
		sniff = content.SniffingRequest
	}
	tag := ""
	listenAddr := xnet.AnyIP
	var listenPort xnet.Port
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		tag = inbound.Tag
		if inbound.Source.Address != nil {
			listenAddr = inbound.Source.Address
		}
		listenPort = inbound.Source.Port
	}
	var sockopt *internet.SocketConfig
	if stream != nil {
		sockopt = stream.SocketSettings
	}

	s := &Server{
		config:     config,
		tlsConfig:  serverTLSConfig(certs, alpn),
		morph:      keys,
		enableTCP:  tcpOn,
		enableUDP:  udpOn,
		userLevel:  config.UserLevel,
		listenAddr: listenAddr,
		listenPort: listenPort,
		sockopt:    sockopt,
		closing:    make(chan struct{}),
	}
	var upstream nwserver.Upstream
	if config.Next != nil && (config.Next.Address != "" || config.Next.Port != 0 || config.Next.Password != "") {
		if config.Next.Alpn == "" {
			config.Next.Alpn = alpn
		}
		nextBundle, err := openBundle(config.Next, xrayDialer{sockopt: sockopt, system: true})
		if err != nil {
			return nil, err
		}
		portal, err := nwserver.NewPortalUpstream(nextBundle)
		if err != nil {
			_ = nextBundle.Close()
			return nil, err
		}
		s.nextBundle = nextBundle
		upstream = portal
	} else {
		raw := v.GetFeature(routing.DispatcherType())
		dispatcher, _ := raw.(routing.Dispatcher)
		if dispatcher == nil {
			return nil, errors.New("nowhere: dispatcher is not available")
		}
		upstream = &dispatchUpstream{dispatcher: dispatcher, tag: tag, level: config.UserLevel, sniff: sniff}
	}
	handler, err := nwserver.NewHandler(nwserver.HandlerOptions{Config: serverConfig, Upstream: upstream})
	if err != nil {
		if s.nextBundle != nil {
			_ = s.nextBundle.Close()
		}
		return nil, err
	}
	s.handler = handler
	return s, nil
}

func parseNetworks(list []string) (tcp bool, udp bool, err error) {
	if len(list) == 0 {
		return true, true, nil
	}
	seen := make(map[string]struct{}, len(list))
	for _, item := range list {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			return false, false, errors.New("nowhere: duplicate network ", item)
		}
		seen[item] = struct{}{}
		switch item {
		case "tcp":
			tcp = true
		case "udp":
			udp = true
		default:
			return false, false, errors.New("nowhere: unsupported network ", item)
		}
	}
	if !tcp && !udp {
		return false, false, errors.New("nowhere: at least one of tcp or udp is required")
	}
	return tcp, udp, nil
}

func (s *Server) Network() []xnet.Network {
	if s.enableTCP {
		return []xnet.Network{xnet.Network_TCP}
	}
	return nil
}

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, _ routing.Dispatcher) error {
	if network != xnet.Network_TCP || !s.enableTCP {
		return errors.New("nowhere: tcp carrier is not enabled")
	}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inbound.Name = "nowhere"
		inbound.CanSpliceCopy = 3
		if inbound.User == nil {
			inbound.User = &protocol.MemoryUser{Level: s.userLevel}
		}
	}
	var raw stdnet.Conn = conn
	if s.morph != nil {
		raw = morph.WrapTCPServer(raw, *s.morph)
	}
	// Split OPEN/ATTACH lanes return from ServeTCP while the sibling lane still
	// owns the socket. Block until the protocol closes it so the TCP worker does
	// not tear the carrier down early.
	watched := &closeSignalConn{Conn: raw, done: make(chan struct{})}
	err := s.handler.ServeTCP(ctx, watched, conn.RemoteAddr(), s.handshake, nil)
	select {
	case <-watched.done:
	case <-s.closing:
	}
	return err
}

func (s *Server) handshake(ctx context.Context, raw stdnet.Conn) (wire.HandshakedConn, error) {
	conn := tls.Server(raw, s.tlsConfig.Clone())
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

func (s *Server) Start() error {
	if !s.enableUDP {
		return nil
	}
	if s.listenPort == 0 {
		return errors.New("nowhere: UDP carrier requires an inbound listen port")
	}
	hub, err := listenQUIC(udpListenAddr(s.listenAddr, s.listenPort), s.sockopt, s.tlsConfig, s.morph, s.handler)
	if err != nil {
		return errors.New("nowhere: failed to listen QUIC").Base(err)
	}
	s.quic = hub
	errors.LogInfo(context.Background(), "nowhere QUIC listening on ", hub.addr)
	return nil
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.closing)
		var errs []error
		if s.quic != nil {
			errs = append(errs, s.quic.Close())
		}
		if s.handler != nil {
			errs = append(errs, s.handler.Close())
		}
		if s.nextBundle != nil {
			errs = append(errs, s.nextBundle.Close())
		}
		s.closeErr = errors.Combine(errs...)
	})
	return s.closeErr
}

type closeSignalConn struct {
	stdnet.Conn
	done chan struct{}
	once sync.Once
}

func (c *closeSignalConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
