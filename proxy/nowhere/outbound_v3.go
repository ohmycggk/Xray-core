package nowhere

import (
	"context"
	stdnet "net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/nowhere/core/morph"
	"github.com/xtls/xray-core/proxy/nowhere/core/qio"
	"github.com/xtls/xray-core/proxy/nowhere/core/vector"
	"github.com/xtls/xray-core/proxy/nowhere/core/wire"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// ClientV3 is the Nowhere 3 Vector client. One endpoint speaks one transport
// toward one Portal; the vendored Vector performs the nw3 handshake on the
// first flow (TCP transport) or on the first dial (UDP transport) and
// multiplexes every later flow over the same session.
type ClientV3 struct {
	config    *ClientConfig
	policy    policy.Manager
	userLevel uint32
	sockopt   *internet.SocketConfig

	mu     sync.Mutex
	client *vector.Client
	closed bool
}

// NewClientV3 builds the Nowhere 3 outbound. The nw2 outbound keeps its own
// constructor; NewClient dispatches between the two by ALPN.
func NewClientV3(ctx context.Context, config *ClientConfig) (*ClientV3, error) {
	if StackFromALPN(config.GetEndpoint().GetAlpn()) != StackNw3 {
		return nil, errors.New("nowhere: Nowhere 3 constructor called with the Nowhere 2 stack")
	}
	ep := config.GetEndpoint()
	if ep == nil || ep.GetAddress() == "" || ep.GetPort() == 0 || ep.GetPassword() == "" {
		return nil, errors.New("nowhere: missing server")
	}
	if err := validateNowhereV3Endpoint(ep); err != nil {
		return nil, err
	}
	if _, err := nowhereV3Net(ep.GetNet()); err != nil {
		return nil, err
	}
	if err := wire.ValidateServiceKey(ep.GetPassword()); err != nil {
		return nil, errors.New("nowhere: password").Base(err)
	}
	stream, err := validateRawStream(ctx)
	if err != nil {
		return nil, err
	}
	v := core.MustFromContext(ctx)
	manager := v.GetFeature(policy.ManagerType()).(policy.Manager)
	c := &ClientV3{
		config:    config,
		policy:    manager,
		userLevel: config.GetUserLevel(),
	}
	if stream != nil {
		c.sockopt = stream.SocketSettings
	}
	return c, nil
}

// ensure builds the vendored Vector on first use, mirroring the nw2 outbound's
// lazy bundle: the carrier dial needs the internet.Dialer Xray hands to
// Process.
func (c *ClientV3) ensure(dialer internet.Dialer) (*vector.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("nowhere: outbound is closed")
	}
	if c.client != nil {
		return c.client, nil
	}
	ep := c.config.GetEndpoint()
	net, err := nowhereV3Net(ep.GetNet())
	if err != nil {
		return nil, err
	}
	tlsConfig, err := buildNowhereV3ClientTLS(ep)
	if err != nil {
		return nil, err
	}
	morphOn := resolveNowhereMorph(ep.Morph, StackNw3)
	var morphKeys *morph.Keys
	if morphOn {
		keys := nowhereV3MorphKeys(ep.GetPassword())
		morphKeys = &keys
	}
	addr := ep.hostport()
	cfg := vector.Config{
		SharedKey:  ep.GetPassword(),
		Morph:      morphOn,
		PortalAddr: addr,
		TLS:        tlsConfig,
	}
	carrierDialer := xrayDialer{dialer: dialer, sockopt: c.sockopt}
	if net == nowhereV3NetTCP {
		cfg.DialTCP = func(dialCtx context.Context, address string) (stdnet.Conn, error) {
			return carrierDialer.DialTCP(dialCtx, address)
		}
	} else {
		cfg.TLS = nil
		cfg.PortalAddr = ""
		cfg.DialQUIC = func(dialCtx context.Context) (qio.Conn, error) {
			return dialNowhereV3QUICCarrier(dialCtx, carrierDialer.DialPacket, addr, tlsConfig, morphKeys)
		}
	}
	client, err := vector.New(cfg)
	if err != nil {
		return nil, err
	}
	c.client = client
	return client, nil
}

func (c *ClientV3) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return errors.New("nowhere: target is not specified")
	}
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("nowhere: target is not specified")
	}
	ob.Name = "nowhere"
	ob.CanSpliceCopy = 3
	target, err := nw3Target(ob.Target)
	if err != nil {
		return err
	}
	client, err := c.ensure(dialer)
	if err != nil {
		return err
	}
	timeouts := c.policy.ForLevel(c.userLevel).Timeouts
	if ob.Target.Network == xnet.Network_UDP {
		return c.processUDP(ctx, client, target, ob.Target, link, timeouts)
	}
	return c.processTCP(ctx, client, target, link, timeouts)
}

func (c *ClientV3) processTCP(ctx context.Context, client *vector.Client, target wire.Target, link *transport.Link, timeouts policy.Timeout) error {
	conn, err := client.OpenTCP(ctx, target)
	if err != nil {
		return errors.New("nowhere: failed to open tcp flow").Base(err)
	}
	defer conn.Close()
	errors.LogInfo(ctx, "nowhere tunneling tcp to ", nw3TargetText(target))
	return relay(ctx, timeouts, link.Reader, buf.NewWriter(conn), &buf.TimeoutWrapperReader{Reader: buf.NewReader(conn)}, link.Writer, func() {
		if half, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
	})
}

func (c *ClientV3) processUDP(ctx context.Context, client *vector.Client, target wire.Target, dest xnet.Destination, link *transport.Link, timeouts policy.Timeout) error {
	conn, err := client.OpenUDP(ctx, target)
	if err != nil {
		return errors.New("nowhere: failed to open udp flow").Base(err)
	}
	defer conn.Close()
	errors.LogInfo(ctx, "nowhere tunneling udp to ", nw3TargetText(target))
	pc := &udpConnPacketConn{Conn: conn, remote: nw3UDPAddr(target)}
	return relay(ctx, timeouts, link.Reader, &packetWriter{pc: pc, addr: nw3UDPAddr(target)}, &buf.TimeoutWrapperReader{Reader: &packetReader{pc: pc, dest: dest}}, link.Writer, nil)
}

func (c *ClientV3) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.client == nil {
		return nil
	}
	err := c.client.Close()
	c.client = nil
	return err
}

var _ proxy.Outbound = (*ClientV3)(nil)

// nw3Target converts an Xray destination into a Nowhere 3 target.
func nw3Target(dest xnet.Destination) (wire.Target, error) {
	if !dest.IsValid() || dest.Address == nil || dest.Port == 0 {
		return wire.Target{}, errors.New("nowhere: target is not specified")
	}
	port := uint16(dest.Port)
	if dest.Address.Family().IsDomain() {
		return wire.NewDomainTarget(dest.Address.Domain(), port)
	}
	ip, ok := netip.AddrFromSlice(dest.Address.IP())
	if !ok {
		return wire.Target{}, errors.New("nowhere: invalid target address")
	}
	return wire.NewIPTarget(ip.Unmap(), port)
}

func nw3TargetText(target wire.Target) string {
	port := strconv.FormatUint(uint64(target.Port), 10)
	if target.IsIP() {
		return stdnet.JoinHostPort(target.Addr.String(), port)
	}
	return stdnet.JoinHostPort(target.Host, port)
}

// udpConnPacketConn presents a connected datagram socket as a net.PacketConn so
// the UDP relay can read and write whole packets.
type udpConnPacketConn struct {
	stdnet.Conn
	remote stdnet.Addr
}

func (c *udpConnPacketConn) ReadFrom(p []byte) (int, stdnet.Addr, error) {
	n, err := c.Conn.Read(p)
	return n, c.remote, err
}

func (c *udpConnPacketConn) WriteTo(p []byte, _ stdnet.Addr) (int, error) {
	return c.Conn.Write(p)
}

var _ stdnet.PacketConn = (*udpConnPacketConn)(nil)
