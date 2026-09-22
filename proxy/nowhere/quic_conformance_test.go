package nowhere

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	nq "github.com/xtls/xray-core/proxy/nowhere/carrier/quic"
	"github.com/xtls/xray-core/proxy/nowhere/carrier/quic/conformance"
	"github.com/xtls/xray-core/proxy/nowhere/wire"
)

// conformanceProbe marks DATAGRAM payloads the test peer must not echo, so
// blocking Send probes cannot pollute the roundtrip receive queue.
const conformanceProbe = "nowhere-conformance-probe"

// conformanceStreamLimit is the server-side incoming stream cap; the
// PrepareStream shutdown probe opens exactly this many streams so the next
// PrepareStream blocks until the session closes.
const conformanceStreamLimit = 8

func TestQUICAdapterConformance(t *testing.T) {
	peer := newConformancePeer(t)
	clientTLS := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{wire.DefaultALPN},
		InsecureSkipVerify: true,
	}
	dial := func(context.Context) (stdnet.PacketConn, stdnet.Addr, error) {
		pc, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		return pc, peer.addr, nil
	}
	backend := newQUICBackend(dial, clientTLS, quicSettings(false, false), nil)
	probeBackend := newQUICBackend(dial, clientTLS, quicSettings(false, false), nil)
	streamBackend := newQUICBackend(dial, clientTLS, quicSettings(false, false), nil)
	t.Cleanup(func() {
		_ = backend.Close()
		_ = probeBackend.Close()
		_ = streamBackend.Close()
	})

	session, err := backend.AcquireSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sess := session.(*quicSession)

	// quic-go makes a stream visible to the peer only when its first STREAM
	// frame is sent, so open-count observations are instrumented adapter-side;
	// the byte-level checks (setup payload, FIN, STOP_SENDING) remain
	// peer-observed through the recorder.
	counted := &countingSession{Session: sess}

	var streamSess *quicSession
	var held []nq.PreparedStream
	t.Cleanup(func() {
		for _, stream := range held {
			_ = stream.Close()
		}
	})

	harness := conformance.FullHarness{
		Harness: conformance.Harness{
			ExpectedALPN: wire.DefaultALPN,
			TLSHandshakeInfo: func() (wire.TLSHandshakeInfo, error) {
				return sess.TLSHandshakeInfo()
			},
			Send: func(ctx context.Context) error {
				for {
					if err := sess.SendDatagram(ctx, []byte(conformanceProbe)); err != nil {
						return err
					}
				}
			},
			Receive: func(ctx context.Context) error {
				_, err := sess.ReceiveDatagram(ctx)
				return err
			},
			Shutdown: func() error {
				sess.close()
				return nil
			},
		},
		Prepared: &conformance.PreparedStreamHarness{
			Session:       counted,
			OpenedStreams: counted.openedCount,
			SetupBytes:    peer.setupBytes,
			WriteFinished: peer.writeFinished,
			ReadCanceled:  peer.readCanceled,
		},
		DatagramRoundTrip: func(ctx context.Context, payload []byte) ([]byte, error) {
			if err := sess.SendDatagram(ctx, payload); err != nil {
				return nil, err
			}
			return sess.ReceiveDatagram(ctx)
		},
		BlockingOperations: []conformance.Operation{
			{
				Name: "AcquireSession",
				Run: func(ctx context.Context) error {
					for {
						acquired, err := probeBackend.AcquireSession(ctx)
						if err != nil {
							return err
						}
						probeBackend.InvalidateSession(acquired)
					}
				},
			},
			{
				Name: "PrepareStream",
				Run: func(ctx context.Context) error {
					if streamSess == nil {
						acquired, err := streamBackend.AcquireSession(ctx)
						if err != nil {
							return err
						}
						streamSess = acquired.(*quicSession)
						for i := 0; i < conformanceStreamLimit; i++ {
							stream, err := streamSess.PrepareStream(context.Background())
							if err != nil {
								return err
							}
							held = append(held, stream)
						}
					}
					stream, err := streamSess.PrepareStream(ctx)
					if err == nil {
						_ = stream.Close()
					}
					return err
				},
			},
		},
		Invalidate: func() error {
			backend.InvalidateSession(sess)
			return nil
		},
		Close: func() error {
			_ = backend.Close()
			_ = probeBackend.Close()
			_ = streamBackend.Close()
			return nil
		},
	}
	if err := conformance.CheckFull(harness); err != nil {
		t.Fatal(err)
	}
}

// countingSession wraps a Session and counts successfully prepared streams.
type countingSession struct {
	nq.Session
	mu     sync.Mutex
	opened int
}

func (s *countingSession) PrepareStream(ctx context.Context) (nq.PreparedStream, error) {
	stream, err := s.Session.PrepareStream(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.opened++
	s.mu.Unlock()
	return stream, nil
}

func (s *countingSession) openedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opened
}

type conformanceStreamRecord struct {
	mu            sync.Mutex
	data          []byte
	fin           bool
	writeCanceled bool
}

func (r *conformanceStreamRecord) append(payload []byte) {
	r.mu.Lock()
	r.data = append(r.data, payload...)
	r.mu.Unlock()
}

func (r *conformanceStreamRecord) snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.data...)
}

// stable waits until the recorded byte count stops growing and returns what
// was captured, so the caller observes exactly the setup payload even though
// the peer reads concurrently.
func (r *conformanceStreamRecord) stable() []byte {
	deadline := time.Now().Add(2 * time.Second)
	last := -1
	quiet := time.Now()
	for time.Now().Before(deadline) {
		n := len(r.snapshot())
		if n != last {
			last = n
			quiet = time.Now()
		} else if n > 0 && time.Since(quiet) >= 30*time.Millisecond {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	return r.snapshot()
}

func (r *conformanceStreamRecord) setFin() {
	r.mu.Lock()
	r.fin = true
	r.mu.Unlock()
}

func (r *conformanceStreamRecord) finSeen() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fin
}

func (r *conformanceStreamRecord) awaitFin() bool {
	deadline := time.Now().Add(300 * time.Millisecond)
	for {
		if r.finSeen() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (r *conformanceStreamRecord) setWriteCanceled() {
	r.mu.Lock()
	r.writeCanceled = true
	r.mu.Unlock()
}

func (r *conformanceStreamRecord) canceled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.writeCanceled
}

func (r *conformanceStreamRecord) awaitCanceled() bool {
	deadline := time.Now().Add(time.Second)
	for {
		if r.canceled() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
}

type conformancePeer struct {
	addr   stdnet.Addr
	tr     *quic.Transport
	ln     *quic.Listener
	pc     stdnet.PacketConn
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	seen    bool
	records []*conformanceStreamRecord
}

func newConformancePeer(t *testing.T) *conformancePeer {
	t.Helper()
	cert, err := generateCertificate()
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{wire.DefaultALPN},
	}
	pc, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	transport := &quic.Transport{Conn: pc, DisableGSO: true}
	listener, err := transport.Listen(tlsConfig, &quic.Config{
		MaxIdleTimeout:        120 * time.Second,
		EnableDatagrams:       true,
		MaxIncomingStreams:    conformanceStreamLimit,
		MaxIncomingUniStreams: 0,
	})
	if err != nil {
		_ = transport.Close()
		_ = pc.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	peer := &conformancePeer{
		addr:   listener.Addr(),
		tr:     transport,
		ln:     listener,
		pc:     pc,
		ctx:    ctx,
		cancel: cancel,
	}
	go peer.acceptLoop()
	t.Cleanup(func() {
		peer.cancel()
		_ = listener.Close()
		_ = transport.Close()
		_ = pc.Close()
	})
	return peer
}

func (p *conformancePeer) acceptLoop() {
	for {
		conn, err := p.ln.Accept(p.ctx)
		if err != nil {
			return
		}
		p.mu.Lock()
		record := !p.seen
		p.seen = true
		p.mu.Unlock()
		go p.serveConn(conn, record)
	}
}

func (p *conformancePeer) serveConn(conn *quic.Conn, record bool) {
	go func() {
		for {
			payload, err := conn.ReceiveDatagram(p.ctx)
			if err != nil {
				return
			}
			if bytes.Equal(payload, []byte(conformanceProbe)) {
				continue
			}
			_ = conn.SendDatagram(payload)
		}
	}()
	for {
		stream, err := conn.AcceptStream(p.ctx)
		if err != nil {
			return
		}
		var rec *conformanceStreamRecord
		if record {
			rec = &conformanceStreamRecord{}
			p.mu.Lock()
			p.records = append(p.records, rec)
			p.mu.Unlock()
		}
		go p.serveStream(stream, rec)
	}
}

func (p *conformancePeer) serveStream(stream *quic.Stream, rec *conformanceStreamRecord) {
	if rec == nil {
		_, _ = io.Copy(io.Discard, stream)
		return
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		// A STOP_SENDING (peer CloseRead) surfaces as a write error.
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := stream.Write([]byte{0}); err != nil {
				rec.setWriteCanceled()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	buffer := make([]byte, 2048)
	for {
		n, err := stream.Read(buffer)
		if n > 0 {
			rec.append(buffer[:n])
		}
		if err != nil {
			if err == io.EOF {
				rec.setFin()
			}
			return
		}
	}
}

func (p *conformancePeer) record(index int) *conformanceStreamRecord {
	deadline := time.Now().Add(2 * time.Second)
	for {
		p.mu.Lock()
		if index >= 0 && index < len(p.records) {
			rec := p.records[index]
			p.mu.Unlock()
			return rec
		}
		p.mu.Unlock()
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (p *conformancePeer) setupBytes(index int) []byte {
	rec := p.record(index)
	if rec == nil {
		return nil
	}
	return rec.stable()
}

func (p *conformancePeer) writeFinished(index int) bool {
	rec := p.record(index)
	if rec == nil {
		return false
	}
	return rec.awaitFin()
}

func (p *conformancePeer) readCanceled(index int) bool {
	rec := p.record(index)
	if rec == nil {
		return false
	}
	return rec.awaitCanceled()
}
