package nowhere

import (
	"context"
	"crypto/tls"
	"io"
	stdnet "net"
	"sync"
	"time"

	goerrors "errors"
	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/proxy/nowhere/carrier"
	"github.com/xtls/xray-core/proxy/nowhere/carrier/morph"
	nq "github.com/xtls/xray-core/proxy/nowhere/carrier/quic"
	nwserver "github.com/xtls/xray-core/proxy/nowhere/server"
	"github.com/xtls/xray-core/proxy/nowhere/wire"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

const defaultDatagramPayload = 1000

type morphKeys = morph.Keys

func deriveMorph(password string) morph.Keys {
	return morph.Derive([]byte(password))
}

func quicSettings(server bool, morphOn bool) *quic.Config {
	cfg := &quic.Config{
		MaxIdleTimeout:                 120 * time.Second,
		KeepAlivePeriod:                15 * time.Second,
		InitialStreamReceiveWindow:     nq.RecommendedStreamReceiveWindow,
		MaxStreamReceiveWindow:         nq.RecommendedStreamReceiveWindow,
		InitialConnectionReceiveWindow: nq.RecommendedConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     nq.RecommendedConnectionReceiveWindow,
		EnableDatagrams:                true,
		DisablePathManager:             true,
		MaxIncomingStreams:             4096,
		MaxIncomingUniStreams:          4096,
	}
	if server {
		cfg.MaxIncomingStreams = 4096
	}
	if morphOn {
		// Morph adds 12 bytes outside QUIC. Pin the packet size at the QUIC minimum
		// so the UDP payload stays within a 1212-byte path.
		cfg.DisablePathMTUDiscovery = true
		cfg.InitialPacketSize = 1200
	}
	return cfg
}

type quicBackend struct {
	dial  func(context.Context) (stdnet.PacketConn, stdnet.Addr, error)
	tls   *tls.Config
	qcfg  *quic.Config
	morph *morph.Keys

	mu         sync.Mutex
	current    *quicSession
	wait       chan struct{}
	dialCancel context.CancelFunc
	closed     bool
}

func newQUICBackend(dial func(context.Context) (stdnet.PacketConn, stdnet.Addr, error), tlsConfig *tls.Config, qcfg *quic.Config, keys *morph.Keys) *quicBackend {
	return &quicBackend{dial: dial, tls: tlsConfig, qcfg: qcfg, morph: keys}
}

func (b *quicBackend) AcquireSession(ctx context.Context) (carrier.QuicSession, error) {
	for {
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			return nil, stdnet.ErrClosed
		}
		if b.current != nil && !b.current.dead() {
			current := b.current
			b.mu.Unlock()
			return current, nil
		}
		if b.current != nil {
			stale := b.current
			b.current = nil
			b.mu.Unlock()
			stale.close()
			continue
		}
		if b.wait != nil {
			wait := b.wait
			b.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		wait := make(chan struct{})
		b.wait = wait
		b.mu.Unlock()

		session, err := b.dialSession(ctx)
		b.mu.Lock()
		b.wait = nil
		close(wait)
		if err != nil {
			b.mu.Unlock()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		if b.closed {
			b.mu.Unlock()
			session.close()
			return nil, stdnet.ErrClosed
		}
		b.current = session
		b.mu.Unlock()
		return session, nil
	}
}

func (b *quicBackend) dialSession(ctx context.Context) (*quicSession, error) {
	dialCtx, cancel := context.WithCancel(context.Background())
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-stop:
		}
	}()
	defer close(stop)

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		cancel()
		return nil, stdnet.ErrClosed
	}
	b.dialCancel = cancel
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.dialCancel = nil
		b.mu.Unlock()
	}()

	pc, raddr, err := b.dial(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	if b.morph != nil {
		pc = morph.WrapPacketConn(pc, b.morph.UDP)
	}
	tr := &quic.Transport{Conn: pc, DisableGSO: true}
	conn, err := tr.Dial(dialCtx, raddr, b.tls.Clone(), b.qcfg)
	if err != nil {
		cancel()
		_ = tr.Close()
		_ = pc.Close()
		return nil, err
	}
	return &quicSession{
		conn:   conn,
		tr:     tr,
		pc:     pc,
		cancel: cancel,
		limit:  datagramLimit{n: defaultDatagramPayload},
	}, nil
}

func (b *quicBackend) InvalidateSession(stale carrier.QuicSession) {
	session, ok := stale.(*quicSession)
	if !ok || session == nil {
		return
	}
	b.mu.Lock()
	if b.current == session {
		b.current = nil
	}
	b.mu.Unlock()
	session.close()
}

func (b *quicBackend) Close() error {
	b.mu.Lock()
	b.closed = true
	current := b.current
	b.current = nil
	dialCancel := b.dialCancel
	b.mu.Unlock()
	if dialCancel != nil {
		dialCancel()
	}
	if current != nil {
		current.close()
	}
	return nil
}

type quicSession struct {
	conn   *quic.Conn
	tr     *quic.Transport
	pc     stdnet.PacketConn
	cancel context.CancelFunc
	limit  datagramLimit
	once   sync.Once
}

func (s *quicSession) dead() bool {
	if s == nil || s.conn == nil {
		return true
	}
	select {
	case <-s.conn.Context().Done():
		return true
	default:
		return false
	}
}

func (s *quicSession) close() {
	s.once.Do(func() {
		if s.conn != nil {
			_ = s.conn.CloseWithError(0, "")
		}
		if s.tr != nil {
			_ = s.tr.Close()
		}
		if s.pc != nil {
			_ = s.pc.Close()
		}
		if s.cancel != nil {
			s.cancel()
		}
	})
}

func (s *quicSession) TLSHandshakeInfo() (wire.TLSHandshakeInfo, error) {
	if s.dead() {
		return wire.TLSHandshakeInfo{}, stdnet.ErrClosed
	}
	return handshakeInfo(s.conn.ConnectionState().TLS)
}

func (s *quicSession) PrepareStream(ctx context.Context) (nq.PreparedStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.dead() {
		return nil, stdnet.ErrClosed
	}
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &preparedStream{stream: stream, local: s.conn.LocalAddr(), remote: s.conn.RemoteAddr()}, nil
}

func (s *quicSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.conn.ReceiveDatagram(ctx)
}

func (s *quicSession) CurrentMaxDatagramSize() int { return s.limit.get() }

func (s *quicSession) SendDatagram(ctx context.Context, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return datagramSendError(s.conn.SendDatagram(payload), &s.limit)
}

func (s *quicSession) LocalAddr() stdnet.Addr {
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

type preparedStream struct {
	once   sync.Once
	stream *quic.Stream
	local  stdnet.Addr
	remote stdnet.Addr
}

func (p *preparedStream) Commit(ctx context.Context, setup []byte, finishWrite bool) (stdnet.Conn, error) {
	var (
		conn stdnet.Conn
		err  error
	)
	p.once.Do(func() {
		if p.stream == nil {
			err = stdnet.ErrClosed
			return
		}
		if ctx != nil && ctx.Err() != nil {
			p.abort()
			err = ctx.Err()
			return
		}
		if werr := writeAll(p.stream, setup); werr != nil {
			p.abort()
			err = werr
			return
		}
		if finishWrite {
			if werr := p.stream.Close(); werr != nil {
				p.stream.CancelRead(0)
				p.stream = nil
				err = werr
				return
			}
		}
		conn = &streamConn{Stream: p.stream, local: p.local, remote: p.remote}
		p.stream = nil
	})
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, stdnet.ErrClosed
	}
	return conn, nil
}

func (p *preparedStream) Close() error {
	var err error
	p.once.Do(func() { err = p.abort() })
	return err
}

func (p *preparedStream) abort() error {
	if p.stream == nil {
		return nil
	}
	p.stream.CancelRead(0)
	p.stream.CancelWrite(0)
	p.stream = nil
	return nil
}

type streamConn struct {
	*quic.Stream
	local  stdnet.Addr
	remote stdnet.Addr
}

func (c *streamConn) LocalAddr() stdnet.Addr  { return c.local }
func (c *streamConn) RemoteAddr() stdnet.Addr { return c.remote }

// CloseRead cancels the read direction; the peer observes a stopped send side.
func (c *streamConn) CloseRead() error {
	c.CancelRead(0)
	return nil
}

// CloseWrite finishes the write direction (QUIC FIN).
func (c *streamConn) CloseWrite() error {
	return c.Stream.Close()
}

func (c *streamConn) Close() error {
	c.CancelRead(0)
	return c.Stream.Close()
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

type datagramLimit struct {
	mu sync.Mutex
	n  int
}

func (l *datagramLimit) get() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n > 0 {
		return l.n
	}
	return defaultDatagramPayload
}

func (l *datagramLimit) set(n int) {
	l.mu.Lock()
	l.n = n
	l.mu.Unlock()
}

type serverQuicConn struct {
	*quic.Conn
	limit datagramLimit
}

func (c *serverQuicConn) TLSHandshakeInfo() (wire.TLSHandshakeInfo, error) {
	return handshakeInfo(c.ConnectionState().TLS)
}

func (c *serverQuicConn) AcceptStream(ctx context.Context) (nwserver.QuicStream, error) {
	stream, err := c.Conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &serverQuicStream{Stream: stream}, nil
}

func (c *serverQuicConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.Conn.ReceiveDatagram(ctx)
}

func (c *serverQuicConn) CurrentMaxDatagramSize() int { return c.limit.get() }

func (c *serverQuicConn) SendDatagram(ctx context.Context, payload []byte) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return datagramSendError(c.Conn.SendDatagram(payload), &c.limit)
}

func datagramSendError(err error, limit *datagramLimit) error {
	if err == nil {
		return nil
	}
	var tooLarge *quic.DatagramTooLargeError
	if goerrors.As(err, &tooLarge) && tooLarge.MaxDatagramPayloadSize > 0 {
		size := int(tooLarge.MaxDatagramPayloadSize)
		if limit != nil {
			limit.set(size)
		}
		return &nq.DatagramTooLargeError{MaxDatagramSize: size, Cause: err}
	}
	return err
}

func (c *serverQuicConn) CloseWithError(code uint64, message string) error {
	return c.Conn.CloseWithError(quic.ApplicationErrorCode(code), message)
}

func (c *serverQuicConn) Close() error {
	return c.Conn.CloseWithError(0, "")
}

func (c *serverQuicConn) Context() context.Context { return c.Conn.Context() }

type serverQuicStream struct {
	*quic.Stream
}

func (s *serverQuicStream) CancelRead(code uint64) {
	s.Stream.CancelRead(quic.StreamErrorCode(code))
}

func (s *serverQuicStream) CancelWrite(code uint64) {
	s.Stream.CancelWrite(quic.StreamErrorCode(code))
}

type quicHub struct {
	listener *quic.Listener
	tr       *quic.Transport
	pc       stdnet.PacketConn
	cancel   context.CancelFunc
	addr     stdnet.Addr
}

func listenQUIC(ctx context.Context, addr *stdnet.UDPAddr, sockopt *internet.SocketConfig, tlsConfig *tls.Config, keys *morph.Keys, handler *nwserver.Handler) (*quicHub, error) {
	pc, err := internet.ListenSystemPacket(ctx, addr, sockopt)
	if err != nil {
		return nil, err
	}
	if keys != nil {
		pc = morph.WrapPacketConn(pc, keys.UDP)
	}
	tr := &quic.Transport{Conn: pc, DisableGSO: true}
	ln, err := tr.Listen(tlsConfig, quicSettings(true, keys != nil))
	if err != nil {
		_ = tr.Close()
		_ = pc.Close()
		return nil, err
	}
	loopCtx, cancel := context.WithCancel(ctx)
	hub := &quicHub{listener: ln, tr: tr, pc: pc, cancel: cancel, addr: ln.Addr()}
	go func() {
		defer cancel()
		for {
			conn, err := ln.Accept(loopCtx)
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				_ = handler.ServeQUIC(loopCtx, &serverQuicConn{Conn: c, limit: datagramLimit{n: defaultDatagramPayload}})
			}(conn)
		}
	}()
	return hub, nil
}

func (h *quicHub) Close() error {
	if h == nil {
		return nil
	}
	if h.cancel != nil {
		h.cancel()
	}
	var errs []error
	if h.listener != nil {
		errs = append(errs, h.listener.Close())
	}
	if h.tr != nil {
		errs = append(errs, h.tr.Close())
	}
	if h.pc != nil {
		errs = append(errs, h.pc.Close())
	}
	return errors.Combine(errs...)
}

func udpListenAddr(address xnet.Address, port xnet.Port) *stdnet.UDPAddr {
	ip := stdnet.IPv4zero
	if address != nil && address.Family().IsIP() {
		ip = address.IP()
	}
	return &stdnet.UDPAddr{IP: ip, Port: int(port)}
}
