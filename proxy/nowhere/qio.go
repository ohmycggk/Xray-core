package nowhere

import (
	"context"
	"crypto/tls"
	stdnet "net"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/proxy/nowhere/core/morph"
	"github.com/xtls/xray-core/proxy/nowhere/core/qio"
	"github.com/xtls/xray-core/proxy/nowhere/core/wire"
	"github.com/xtls/xray-core/transport/internet"
)

// nowhereV3MaxDatagramSize is the fragment size the vendored core uses when it
// splits a UDP payload across QUIC DATAGRAM frames. The host cannot read
// quic-go's dynamic payload estimate, so the value is pinned below the smallest
// path-MTU-derived bound, the same conservative choice the nw2 carrier makes.
const nowhereV3MaxDatagramSize = 1000

// qioStream adapts *quic.Stream to the vendored qio.Stream. quic-go's Close
// sends FIN and keeps the receive side open, which is exactly CloseWrite; a
// full Close additionally aborts the receive side, like the reference CLI.
type qioStream struct {
	*quic.Stream
}

var _ qio.Stream = (*qioStream)(nil)

func (s *qioStream) CloseWrite() error { return s.Stream.Close() }

func (s *qioStream) Close() error {
	s.CancelRead(0)
	return s.Stream.Close()
}

func (s *qioStream) ID() uint64 { return uint64(s.Stream.StreamID()) }

// qioConn adapts *quic.Conn to the vendored qio.Conn.
type qioConn struct {
	conn *quic.Conn
}

var _ qio.Conn = (*qioConn)(nil)

func newQIOConn(conn *quic.Conn) *qioConn {
	return &qioConn{conn: conn}
}

func (c *qioConn) TLSVersion() uint16 { return c.conn.ConnectionState().TLS.Version }
func (c *qioConn) ALPN() string       { return c.conn.ConnectionState().TLS.NegotiatedProtocol }

func (c *qioConn) Exporter() ([]byte, error) {
	state := c.conn.ConnectionState().TLS
	return (&state).ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
}

func (c *qioConn) AcceptStream(ctx context.Context) (qio.Stream, error) {
	stream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &qioStream{Stream: stream}, nil
}

func (c *qioConn) OpenStream(ctx context.Context) (qio.Stream, error) {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &qioStream{Stream: stream}, nil
}

func (c *qioConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.conn.ReceiveDatagram(ctx)
}

func (c *qioConn) SendDatagram(b []byte) error { return c.conn.SendDatagram(b) }

func (c *qioConn) MaxDatagramSize() int { return nowhereV3MaxDatagramSize }

func (c *qioConn) CloseWithError(code uint64, message string) error {
	return c.conn.CloseWithError(quic.ApplicationErrorCode(code), message)
}

func (c *qioConn) Context() context.Context { return c.conn.Context() }
func (c *qioConn) RemoteAddr() stdnet.Addr  { return c.conn.RemoteAddr() }

// qioListener adapts *quic.Listener to the vendored qio.Listener.
type qioListener struct {
	listener *quic.Listener
}

var _ qio.Listener = (*qioListener)(nil)

func (l *qioListener) Accept(ctx context.Context) (qio.Conn, error) {
	conn, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return newQIOConn(conn), nil
}

func (l *qioListener) Close() error { return l.listener.Close() }

// connectedPacketConn presents a connected UDP socket as a net.PacketConn so
// the Nowhere 3 Morph wrapper can seal it below QUIC.
type connectedPacketConn struct {
	stdnet.Conn
	remote stdnet.Addr
}

func (c *connectedPacketConn) ReadFrom(p []byte) (int, stdnet.Addr, error) {
	n, err := c.Conn.Read(p)
	return n, c.remote, err
}

func (c *connectedPacketConn) WriteTo(p []byte, _ stdnet.Addr) (int, error) {
	return c.Conn.Write(p)
}

// dialNowhereV3QUICCarrier opens the QUIC carrier for the Vector/Egress client.
// Morph seals the packet socket below QUIC on the host side; the TLS config
// already pins TLS 1.3 and ALPN nw3 with session resumption disabled.
func dialNowhereV3QUICCarrier(ctx context.Context, dial func(context.Context, string) (stdnet.PacketConn, stdnet.Addr, error), addr string, tlsConfig *tls.Config, keys *morph.Keys) (qio.Conn, error) {
	packetConn, remote, err := dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	if keys != nil {
		packetConn = morph.WrapPacketConn(packetConn, *keys, true)
	}
	tr := &quic.Transport{Conn: packetConn, DisableGSO: true}
	qconn, err := tr.Dial(ctx, remote, tlsConfig.Clone(), quicSettings(false, keys != nil))
	if err != nil {
		_ = tr.Close()
		_ = packetConn.Close()
		return nil, err
	}
	return newQIOConn(qconn), nil
}

// listenNowhereV3QUIC starts the non-Early QUIC listener for the Portal. Morph
// seals the listening socket below QUIC when enabled.
func listenNowhereV3QUIC(ctx context.Context, packetConn stdnet.PacketConn, tlsConfig *tls.Config, keys *morph.Keys) (qio.Listener, error) {
	if keys != nil {
		packetConn = morph.WrapPacketConn(packetConn, *keys, false)
	}
	tr := &quic.Transport{Conn: packetConn, DisableGSO: true}
	listener, err := tr.Listen(tlsConfig, quicSettings(true, keys != nil))
	if err != nil {
		_ = tr.Close()
		_ = packetConn.Close()
		return nil, err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	return &qioListener{listener: listener}, nil
}

// udpCarrierSocket opens the listening UDP socket the QUIC carrier needs.
func udpCarrierSocket(ctx context.Context, addr *stdnet.UDPAddr, sockopt *internet.SocketConfig) (stdnet.PacketConn, error) {
	return internet.ListenSystemPacket(ctx, addr, sockopt)
}
