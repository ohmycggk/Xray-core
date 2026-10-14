package nowhere

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	stdnet "net"
	"os"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/nowhere/core/morph"
	nw2wire "github.com/xtls/xray-core/proxy/nowhere/core/nw2/wire"
	"github.com/xtls/xray-core/proxy/nowhere/core/portal"
	"github.com/xtls/xray-core/proxy/nowhere/core/wire"
	"github.com/xtls/xray-core/transport"
)

// nowhereVersion2 and nowhereVersion3 select the protocol stack of one endpoint.
// The two stacks share no handshake: a single inbound/outbound runs exactly one
// version, and nw2-only fields are rejected when version 3 is selected.
const (
	nowhereVersion2 = 2
	nowhereVersion3 = 3
)

// resolveNowhereVersion maps the raw version option to a stack. Zero means 2,
// which keeps every pre-nw3 configuration working unchanged.
func resolveNowhereVersion(raw int32) (int, error) {
	switch raw {
	case 0, nowhereVersion2:
		return nowhereVersion2, nil
	case nowhereVersion3:
		return nowhereVersion3, nil
	default:
		return 0, errors.New("nowhere: version must be 2 or 3, got ", raw)
	}
}

// resolveNowhereMorph applies the per-version Morph default: Nowhere 2 leaves
// the transform off, Nowhere 3 turns it on. An explicit value always wins.
func resolveNowhereMorph(raw *bool, version int) bool {
	if raw != nil {
		return *raw
	}
	return version == nowhereVersion3
}

// nowhereV3CarrierTCP and nowhereV3CarrierQUIC are the two Nowhere 3
// transports. Nowhere 3 speaks exactly one of them per endpoint.
const (
	nowhereV3CarrierTCP  = "tcp"
	nowhereV3CarrierQUIC = "quic"
)

// nowhereV3Carrier resolves the single Nowhere 3 carrier. Nowhere 3 uses
// exactly one transport: tcp (TLS over TCP) or quic. Empty means tcp.
func nowhereV3Carrier(raw string) (string, error) {
	switch raw {
	case "", nowhereV3CarrierTCP:
		return nowhereV3CarrierTCP, nil
	case nowhereV3CarrierQUIC:
		return nowhereV3CarrierQUIC, nil
	default:
		return "", errors.New("nowhere: version 3 carrier must be tcp or quic, got ", raw)
	}
}

// validateNowhereV3Endpoint rejects the nw2-only endpoint fields Nowhere 3
// cannot honor: the vendored Vector speaks one carrier with fixed pooling, so
// up/down, the mux toggle, the pool size, the negotiated ALPN list and the
// dual-stack dial policy have no Nowhere 3 meaning.
func validateNowhereV3Endpoint(ep *Endpoint) error {
	if ep.GetUp() != "" || ep.GetDown() != "" {
		return errors.New("nowhere: version 3 uses one carrier; remove up and down")
	}
	if ep.GetMux() {
		return errors.New("nowhere: version 3 has no multiplexing; remove mux")
	}
	if ep.GetPool() != 0 {
		return errors.New("nowhere: version 3 has no connection pool; remove pool")
	}
	if ep.GetAlpn() != "" {
		return errors.New("nowhere: version 3 fixes ALPN to ", wire.ALPN, "; remove alpn")
	}
	if ep.GetDial4() != "" || ep.GetDial6() != "" {
		return errors.New("nowhere: version 3 has no dial4/dial6 source binding; remove them")
	}
	return nil
}

// validateNowhereV3Server rejects the nw2-only server fields: the vendored
// Portal owns its own admission limits and speaks only nw3, and Nowhere 3 has
// no native Portal chaining.
func validateNowhereV3Server(config *ServerConfig) error {
	if config.GetNext() != nil {
		return errors.New("nowhere: version 3 does not support next chaining")
	}
	if config.GetAlpn() != "" {
		return errors.New("nowhere: version 3 fixes ALPN to ", wire.ALPN, "; remove alpn")
	}
	return nil
}

// validateNowhereV3Networks keeps the network list consistent with the single
// Nowhere 3 carrier: the carrier already decides TCP or UDP, so an explicit
// network list may only name that one transport.
func validateNowhereV3Networks(networks []string, carrier string) error {
	if len(networks) == 0 {
		return nil
	}
	expected := "tcp"
	if carrier == nowhereV3CarrierQUIC {
		expected = "udp"
	}
	if len(networks) != 1 || networks[0] != expected {
		return errors.New("nowhere: version 3 carrier ", carrier, " implies network ", expected, "; remove networks or set it to ", expected)
	}
	return nil
}

// buildNowhereV3ClientTLS produces the standard-library client config the
// vendored Vector uses for the TLS carrier and for QUIC dials. Trust follows
// Nowhere 3: system roots plus the endpoint host name by default, pin overrides
// everything, and the explicit insecure escape hatch skips verification.
func buildNowhereV3ClientTLS(ep *Endpoint) (*tls.Config, error) {
	name := ep.GetServerName()
	if name == "" && stdnet.ParseIP(ep.GetAddress()) == nil {
		name = ep.GetAddress()
	}
	cfg := &tls.Config{
		ServerName:         name,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{wire.ALPN},
		ClientSessionCache: nil,
		InsecureSkipVerify: ep.GetAllowInsecure(),
	}
	if pin := ep.GetPin(); pin != "" {
		verify, err := nw2wire.PeerCertificatePinVerifier(pin)
		if err != nil {
			return nil, err
		}
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = verify
	}
	return cfg, nil
}

// buildNowhereV3ServerTLS produces the standard-library server config the
// vendored Portal uses for its own handshakes on both carriers.
func buildNowhereV3ServerTLS(certs []tls.Certificate) *tls.Config {
	cfg := serverTLSConfig(certs, wire.ALPN)
	// The vendored stack performs its own handshakes, so resumption stays off
	// on both carriers.
	cfg.SessionTicketsDisabled = true
	return cfg
}

// logNowhereV3PortalFingerprint prints the leaf certificate SHA-256 so users
// can obtain a pin= value, matching the reference Portal's startup log.
func logNowhereV3PortalFingerprint(ctx context.Context, tlsConfig *tls.Config) {
	if tlsConfig == nil || len(tlsConfig.Certificates) == 0 {
		return
	}
	leaf := tlsConfig.Certificates[0].Leaf
	if leaf == nil && len(tlsConfig.Certificates[0].Certificate) > 0 {
		if parsed, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0]); err == nil {
			leaf = parsed
		}
	}
	if leaf == nil {
		return
	}
	errors.LogInfo(ctx, "nowhere TLS certificate SHA-256 fingerprint: ", nw2wire.LeafCertificateSHA256Hex(leaf.Raw))
}

// nowhereV3MorphKeys derives the Nowhere 3 Morph keys. The TCP carrier is
// wrapped inside the vendored Vector/Portal, so only QUIC dials and QUIC
// listeners need this host-side derivation.
func nowhereV3MorphKeys(password string) morph.Keys {
	return morph.Derive([]byte(password))
}

// nw3Upstream adapts the Xray dispatcher to the Nowhere 3 Upstream interface
// shared by the Portal (normal mode) and the Egress client. Both receive a
// target only, so the source address is left unspecified.
type nw3Upstream struct {
	dispatcher routing.Dispatcher
	tag        string
	level      uint32
	sniff      session.SniffingRequest
}

var _ portal.Upstream = (*nw3Upstream)(nil)

func (u *nw3Upstream) DialTCP(ctx context.Context, target wire.Target) (stdnet.Conn, error) {
	dest, err := nw3DestinationFromTarget(target, xnet.Network_TCP)
	if err != nil {
		return nil, err
	}
	ctx = u.decorate(ctx)
	local, remote := stdnet.Pipe()
	link := &transport.Link{
		Reader: buf.NewReader(remote),
		Writer: buf.NewWriter(remote),
	}
	go func() {
		_ = u.dispatcher.DispatchLink(ctx, dest, link)
		_ = remote.Close()
	}()
	return local, nil
}

func (u *nw3Upstream) DialUDP(ctx context.Context, target wire.Target) (stdnet.Conn, error) {
	dest, err := nw3DestinationFromTarget(target, xnet.Network_UDP)
	if err != nil {
		return nil, err
	}
	ctx = u.decorate(ctx)
	pipe := newUDPPipe()
	link := &transport.Link{
		Reader: &packetReader{pc: pipe, dest: dest},
		Writer: &packetWriter{pc: pipe, addr: nw3UDPAddr(target)},
	}
	go func() {
		_ = u.dispatcher.DispatchLink(ctx, dest, link)
		_ = pipe.Close()
	}()
	return pipe.netConn(), nil
}

func (u *nw3Upstream) decorate(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	var inbound session.Inbound
	if existing := session.InboundFromContext(ctx); existing != nil {
		inbound = *existing
	}
	inbound.Name = "nowhere"
	inbound.CanSpliceCopy = 3
	if inbound.Tag == "" {
		inbound.Tag = u.tag
	}
	if inbound.User == nil {
		inbound.User = &protocol.MemoryUser{Level: u.level}
	}
	ctx = session.ContextWithInbound(ctx, &inbound)
	if session.ContentFromContext(ctx) == nil {
		ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: u.sniff})
	}
	if len(session.OutboundsFromContext(ctx)) == 0 {
		ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	}
	return ctx
}

// nw3DestinationFromTarget converts a Nowhere 3 target into an Xray
// destination, mirroring the nw2 helper for the nw3 wire type.
func nw3DestinationFromTarget(target wire.Target, network xnet.Network) (xnet.Destination, error) {
	if target.Port == 0 {
		return xnet.Destination{}, errors.New("nowhere: target is not specified")
	}
	if target.IsIP() {
		if !target.Addr.IsValid() {
			return xnet.Destination{}, errors.New("nowhere: invalid target address")
		}
		return xnet.Destination{Network: network, Address: xnet.IPAddress(target.Addr.AsSlice()), Port: xnet.Port(target.Port)}, nil
	}
	if target.Host == "" {
		return xnet.Destination{}, errors.New("nowhere: target is not specified")
	}
	return xnet.Destination{Network: network, Address: xnet.DomainAddress(target.Host), Port: xnet.Port(target.Port)}, nil
}

func nw3UDPAddr(target wire.Target) stdnet.Addr {
	if target.Addr.IsValid() {
		return &stdnet.UDPAddr{IP: target.Addr.AsSlice(), Port: int(target.Port)}
	}
	return &stdnet.UDPAddr{IP: stdnet.IPv4zero, Port: int(target.Port)}
}

// udpPipe is an in-memory PacketConn whose packets cross a channel pair. The
// dispatcher side reads and writes packets through the PacketConn methods
// while the Nowhere 3 upstream sees a datagram-oriented net.Conn: one
// Read/Write moves exactly one packet.
type udpPipe struct {
	// uplink carries user-to-target packets: the protocol side hands them over
	// with Write and the dispatcher drains them with ReadFrom.
	uplink chan []byte
	// downlink carries target-to-user packets: the dispatcher hands them over
	// with WriteTo and the protocol side drains them with Read.
	downlink chan []byte
	closed   chan struct{}

	closeOnce     sync.Once
	readDeadline  pipeDeadline
	writeDeadline pipeDeadline
}

var _ stdnet.PacketConn = (*udpPipe)(nil)

func newUDPPipe() *udpPipe {
	return &udpPipe{
		uplink:        make(chan []byte, 64),
		downlink:      make(chan []byte, 64),
		closed:        make(chan struct{}),
		readDeadline:  makePipeDeadline(),
		writeDeadline: makePipeDeadline(),
	}
}

func (p *udpPipe) ReadFrom(buffer []byte) (int, stdnet.Addr, error) {
	select {
	case payload := <-p.uplink:
		return copy(buffer, payload), nil, nil
	case <-p.closed:
		return 0, nil, stdnet.ErrClosed
	case <-p.readDeadline.wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (p *udpPipe) WriteTo(payload []byte, _ stdnet.Addr) (int, error) {
	packet := make([]byte, len(payload))
	copy(packet, payload)
	select {
	case p.downlink <- packet:
		return len(payload), nil
	case <-p.closed:
		return 0, stdnet.ErrClosed
	case <-p.writeDeadline.wait():
		return 0, os.ErrDeadlineExceeded
	}
}

func (p *udpPipe) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *udpPipe) LocalAddr() stdnet.Addr { return &stdnet.UDPAddr{} }

func (p *udpPipe) SetDeadline(t time.Time) error {
	p.readDeadline.set(t)
	p.writeDeadline.set(t)
	return nil
}

func (p *udpPipe) SetReadDeadline(t time.Time) error {
	p.readDeadline.set(t)
	return nil
}

func (p *udpPipe) SetWriteDeadline(t time.Time) error {
	p.writeDeadline.set(t)
	return nil
}

// udpPipeConn is the datagram-oriented net.Conn facade the Nowhere 3 upstream
// uses on the protocol side of a udpPipe. Its directions are opposite to the
// PacketConn methods: a Write hands a user-to-target packet to the dispatcher
// (it lands on the channel ReadFrom drains), and a Read takes a
// target-to-user packet the dispatcher wrote (from the channel WriteTo feeds).
type udpPipeConn struct {
	*udpPipe
}

func (p *udpPipe) netConn() stdnet.Conn {
	return &udpPipeConn{udpPipe: p}
}

func (c *udpPipeConn) Read(buffer []byte) (int, error) {
	select {
	case payload := <-c.downlink:
		return copy(buffer, payload), nil
	case <-c.closed:
		return 0, stdnet.ErrClosed
	case <-c.readDeadline.wait():
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *udpPipeConn) Write(payload []byte) (int, error) {
	packet := make([]byte, len(payload))
	copy(packet, payload)
	select {
	case c.uplink <- packet:
		return len(payload), nil
	case <-c.closed:
		return 0, stdnet.ErrClosed
	case <-c.writeDeadline.wait():
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *udpPipeConn) RemoteAddr() stdnet.Addr { return &stdnet.UDPAddr{} }

var _ stdnet.Conn = (*udpPipeConn)(nil)

// pipeDeadline is a channel-based deadline: wait returns a channel that closes
// once the deadline passes or is moved, and a zero time disarms it.
type pipeDeadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	expire chan struct{}
}

func makePipeDeadline() pipeDeadline {
	return pipeDeadline{expire: make(chan struct{})}
}

func (d *pipeDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	// Re-arm so a wait already blocked on the old channel wakes up.
	close(d.expire)
	d.expire = make(chan struct{})
	if t.IsZero() {
		return
	}
	delay := time.Until(t)
	if delay <= 0 {
		close(d.expire)
		return
	}
	current := d.expire
	d.timer = time.AfterFunc(delay, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		select {
		case <-current:
		default:
			close(current)
		}
	})
}

func (d *pipeDeadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.expire
}
