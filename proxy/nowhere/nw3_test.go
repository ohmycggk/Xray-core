package nowhere

import (
	"bytes"
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"

	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/udp"
)

// testNw3Key is a Nowhere 3 service key: exactly 32 lowercase hex characters.
// The nw2 keys in nowhere_test.go are deliberately not reused here: the two
// stacks have different key rules and must not be mixed.
const testNw3Key = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

func TestResolveNowhereVersion(t *testing.T) {
	for _, testCase := range []struct {
		raw     int32
		version int
	}{
		{0, nowhereVersion2},
		{nowhereVersion2, nowhereVersion2},
		{nowhereVersion3, nowhereVersion3},
	} {
		version, err := resolveNowhereVersion(testCase.raw)
		if err != nil {
			t.Fatal(err)
		}
		if version != testCase.version {
			t.Fatalf("version %d -> %d", testCase.raw, version)
		}
	}
	for _, raw := range []int32{1, 4, -1} {
		if _, err := resolveNowhereVersion(raw); err == nil {
			t.Fatalf("version %d accepted", raw)
		}
	}
}

func TestResolveNowhereMorph(t *testing.T) {
	if resolveNowhereMorph(nil, nowhereVersion2) {
		t.Fatal("nw2 must default morph off")
	}
	if !resolveNowhereMorph(nil, nowhereVersion3) {
		t.Fatal("nw3 must default morph on")
	}
	on, off := true, false
	if !resolveNowhereMorph(&on, nowhereVersion2) {
		t.Fatal("explicit on must win")
	}
	if resolveNowhereMorph(&off, nowhereVersion3) {
		t.Fatal("explicit off must win")
	}
}

func TestNowhereV3Carrier(t *testing.T) {
	for _, testCase := range []struct {
		raw     string
		carrier string
	}{
		{"", nowhereV3CarrierTCP},
		{"tcp", nowhereV3CarrierTCP},
		{"quic", nowhereV3CarrierQUIC},
	} {
		carrier, err := nowhereV3Carrier(testCase.raw)
		if err != nil {
			t.Fatal(err)
		}
		if carrier != testCase.carrier {
			t.Fatalf("carrier %q -> %q", testCase.raw, carrier)
		}
	}
	if _, err := nowhereV3Carrier("ws"); err == nil {
		t.Fatal("expected carrier rejection")
	}
}

func TestValidateNowhereV3Endpoint(t *testing.T) {
	base := func() *Endpoint {
		return &Endpoint{Address: "127.0.0.1", Port: 443, Password: testNw3Key}
	}
	if err := validateNowhereV3Endpoint(base()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Endpoint){
		"up":    func(e *Endpoint) { e.Up = "tcp" },
		"down":  func(e *Endpoint) { e.Down = "udp" },
		"mux":   func(e *Endpoint) { e.Mux = true },
		"pool":  func(e *Endpoint) { e.Pool = 4 },
		"alpn":  func(e *Endpoint) { e.Alpn = "nw3" },
		"dial4": func(e *Endpoint) { e.Dial4 = "127.0.0.1" },
		"dial6": func(e *Endpoint) { e.Dial6 = "::1" },
	} {
		t.Run(name, func(t *testing.T) {
			ep := base()
			mutate(ep)
			if err := validateNowhereV3Endpoint(ep); err == nil {
				t.Fatal("expected nw2-only field rejection")
			}
		})
	}
}

func TestValidateNowhereV3Server(t *testing.T) {
	if err := validateNowhereV3Server(&ServerConfig{Password: testNw3Key}); err != nil {
		t.Fatal(err)
	}
	if err := validateNowhereV3Server(&ServerConfig{Next: &Endpoint{}}); err == nil {
		t.Fatal("expected next chaining rejection")
	}
	if err := validateNowhereV3Server(&ServerConfig{Alpn: "nw3"}); err == nil {
		t.Fatal("expected alpn rejection")
	}
}

func TestValidateNowhereV3Networks(t *testing.T) {
	for _, testCase := range []struct {
		networks []string
		carrier  string
	}{
		{nil, nowhereV3CarrierTCP},
		{[]string{"tcp"}, nowhereV3CarrierTCP},
		{[]string{"udp"}, nowhereV3CarrierQUIC},
	} {
		if err := validateNowhereV3Networks(testCase.networks, testCase.carrier); err != nil {
			t.Fatalf("networks %v carrier %s: %v", testCase.networks, testCase.carrier, err)
		}
	}
	for _, testCase := range []struct {
		networks []string
		carrier  string
	}{
		{[]string{"udp"}, nowhereV3CarrierTCP},
		{[]string{"tcp"}, nowhereV3CarrierQUIC},
		{[]string{"tcp", "udp"}, nowhereV3CarrierTCP},
	} {
		if err := validateNowhereV3Networks(testCase.networks, testCase.carrier); err == nil {
			t.Fatalf("networks %v carrier %s accepted", testCase.networks, testCase.carrier)
		}
	}
}

// TestNewServerV3RejectsUnsupportedFields drives the version 3 constructor
// directly so every rejection path is covered without a running Portal.
func TestNewServerV3RejectsUnsupportedFields(t *testing.T) {
	ctx := newNw3TestContext(t)
	base := func() *ServerConfig {
		return &ServerConfig{Password: testNw3Key, Version: nowhereVersion3}
	}
	for name, mutate := range map[string]func(*ServerConfig){
		"version":       func(c *ServerConfig) { c.Version = 5 },
		"carrier":       func(c *ServerConfig) { c.Carrier = "ws" },
		"key":           func(c *ServerConfig) { c.Password = "xyz" },
		"key-length":    func(c *ServerConfig) { c.Password = testNw3Key + "01234567" },
		"missing-key":   func(c *ServerConfig) { c.Password = "" },
		"next":          func(c *ServerConfig) { c.Next = &Endpoint{} },
		"alpn":          func(c *ServerConfig) { c.Alpn = "nw3" },
		"network":       func(c *ServerConfig) { c.Networks = []string{"udp"} },
		"egress-on-tcp": func(c *ServerConfig) { c.Egress = true },
	} {
		t.Run(name, func(t *testing.T) {
			config := base()
			mutate(config)
			if _, err := NewServerV3(ctx, config); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestNewClientV3RejectsUnsupportedFields(t *testing.T) {
	ctx := newNw3TestContext(t)
	base := func() *ClientConfig {
		return &ClientConfig{Endpoint: &Endpoint{
			Address:       "127.0.0.1",
			Port:          443,
			Password:      testNw3Key,
			AllowInsecure: true,
			Version:       nowhereVersion3,
		}}
	}
	for name, mutate := range map[string]func(*ClientConfig){
		"version":    func(c *ClientConfig) { c.Endpoint.Version = 5 },
		"carrier":    func(c *ClientConfig) { c.Endpoint.Carrier = "ws" },
		"password":   func(c *ClientConfig) { c.Endpoint.Password = "" },
		"key":        func(c *ClientConfig) { c.Endpoint.Password = "xyz" },
		"key-length": func(c *ClientConfig) { c.Endpoint.Password = testNw3Key + "01234567" },
		"up":         func(c *ClientConfig) { c.Endpoint.Up = "tcp" },
		"down":       func(c *ClientConfig) { c.Endpoint.Down = "tcp" },
		"mux":        func(c *ClientConfig) { c.Endpoint.Mux = true },
		"pool":       func(c *ClientConfig) { c.Endpoint.Pool = 4 },
		"alpn":       func(c *ClientConfig) { c.Endpoint.Alpn = "nw3" },
		"dial4":      func(c *ClientConfig) { c.Endpoint.Dial4 = "127.0.0.1" },
	} {
		t.Run(name, func(t *testing.T) {
			config := base()
			mutate(config)
			if _, err := NewClientV3(ctx, config); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

// TestNowhereDispatchSelectsStack proves NewServer and NewClient route each
// version to its own stack and that a bad version is rejected before either
// constructor runs.
func TestNowhereDispatchSelectsStack(t *testing.T) {
	ctx := newNw3TestContext(t)
	server, err := NewServer(ctx, &ServerConfig{Password: testNw3Key, Version: nowhereVersion3})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := server.(*ServerV3); !ok {
		t.Fatalf("version 3 server is %T", server)
	}
	legacy, err := NewServer(ctx, &ServerConfig{Password: "0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := legacy.(*Server); !ok {
		t.Fatalf("version 2 server is %T", legacy)
	}
	if _, err := NewServer(ctx, &ServerConfig{Password: testNw3Key, Version: 7}); err == nil {
		t.Fatal("expected version rejection")
	}

	client, err := NewClient(ctx, &ClientConfig{Endpoint: &Endpoint{
		Address: "127.0.0.1", Port: 443, Password: testNw3Key, AllowInsecure: true, Version: nowhereVersion3,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := client.(*ClientV3); !ok {
		t.Fatalf("version 3 client is %T", client)
	}
	legacyClient, err := NewClient(ctx, &ClientConfig{Endpoint: &Endpoint{
		Address: "127.0.0.1", Port: 443, Password: "secret", AllowInsecure: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := legacyClient.(*Client); !ok {
		t.Fatalf("version 2 client is %T", legacyClient)
	}
	if _, err := NewClient(ctx, &ClientConfig{Endpoint: &Endpoint{
		Address: "127.0.0.1", Port: 443, Password: "secret", Version: 7,
	}}); err == nil {
		t.Fatal("expected version rejection")
	}
}

// TestNowhereV3TCPForwarding runs a full Nowhere 3 endpoint pair over the TCP
// carrier with Morph on (the v3 default): the vendored Portal hands every
// authenticated flow to the Xray dispatcher, which serves it from the local
// freedom outbound. TCP flows and UDP flows carried as UoT both round-trip.
func TestNowhereV3TCPForwarding(t *testing.T) {
	echoPort := startTCPEcho(t)
	udpPort := startUDPEcho(t)
	serverPort := freePort(t)
	startV3Portal(t, serverPort, testNw3Key, nowhereV3CarrierTCP, nil, false, nil)
	handler := startV3Client(t, serverPort, testNw3Key, nowhereV3CarrierTCP, nil)

	assertV3TCP(t, handler, echoPort)
	assertV3UDP(t, handler, udpPort)
}

// TestNowhereV3MorphOff runs the same pair with Morph explicitly disabled on
// both ends, so both transform settings interoperate on the TCP carrier.
func TestNowhereV3MorphOff(t *testing.T) {
	echoPort := startTCPEcho(t)
	serverPort := freePort(t)
	off := false
	startV3Portal(t, serverPort, testNw3Key, nowhereV3CarrierTCP, &off, false, nil)
	handler := startV3Client(t, serverPort, testNw3Key, nowhereV3CarrierTCP, &off)
	assertV3TCP(t, handler, echoPort)
}

// newNw3TestContext returns a context carrying a Xray instance, which is what
// the nw3 constructors read the dispatcher and policy manager from.
func newNw3TestContext(t *testing.T) context.Context {
	t.Helper()
	inst, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&policy.Config{}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	return context.WithValue(context.Background(), xrayKey, inst)
}

// xrayKey mirrors core.xrayKey: it is the context key an Instance is stored
// under, and core only exposes it for tests.
const xrayKey core.XrayKey = 1

// startV3Portal brings up a Nowhere 3 Portal inbound on port. Morph nil keeps
// the Nowhere 3 default (on); networks restricts the inbound listener.
func startV3Portal(t *testing.T, port int, password, carrier string, morph *bool, egress bool, networks []string) {
	t.Helper()
	inst, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&policy.Config{}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			Tag: "nowhere",
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(port))}},
				Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&ServerConfig{
				Password: password,
				Version:  nowhereVersion3,
				Carrier:  carrier,
				Morph:    morph,
				Egress:   egress,
				Networks: networks,
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag:           "direct",
			ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inst.Close() })
}

// startV3Client brings up a Nowhere 3 outbound and returns its handler. Morph
// nil keeps the Nowhere 3 default (on).
func startV3Client(t *testing.T, port int, password, carrier string, morph *bool) outbound.Handler {
	t.Helper()
	inst, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&policy.Config{}),
		},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: "nw",
			ProxySettings: serial.ToTypedMessage(&ClientConfig{Endpoint: &Endpoint{
				Address:       "127.0.0.1",
				Port:          uint32(port),
				Password:      password,
				Version:       nowhereVersion3,
				Carrier:       carrier,
				Morph:         morph,
				AllowInsecure: true,
			}}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	handler := inst.GetFeature(outbound.ManagerType()).(outbound.Manager).GetHandler("nw")
	if handler == nil {
		t.Fatal("missing nowhere outbound")
	}
	return handler
}

func assertV3TCP(t *testing.T, handler outbound.Handler, port int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dest := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(port))
	uplinkReader, uplinkWriter := pipe.New()
	downlinkReader, downlinkWriter := pipe.New()
	go handler.Dispatch(session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}}), &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	})

	payload := bytes.Repeat([]byte("nw3"), 2048)
	packet := buf.New()
	packet.Write(payload)
	if err := uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
		t.Fatal(err)
	}
	merged := readFullMultiBuffer(t, downlinkReader, len(payload))
	if !bytes.Equal(merged, payload) {
		t.Fatalf("tcp payload mismatch: got %d bytes", len(merged))
	}
	_ = uplinkWriter.Close()
	_ = downlinkWriter.Close()
}

func assertV3UDP(t *testing.T, handler outbound.Handler, port int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dest := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(port))
	uplinkReader, uplinkWriter := pipe.New()
	downlinkReader, downlinkWriter := pipe.New()
	go handler.Dispatch(session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}}), &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	})

	payload := bytes.Repeat([]byte("u"), 2000)
	packet := buf.New()
	packet.Write(payload)
	if err := uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
		t.Fatal(err)
	}
	merged := readFullMultiBuffer(t, downlinkReader, len(payload))
	if !bytes.Equal(merged, payload) {
		t.Fatalf("udp payload mismatch: got %d bytes", len(merged))
	}
	_ = uplinkWriter.Close()
	_ = downlinkWriter.Close()
}

// readFullMultiBuffer drains reader until want bytes arrived. A single read may
// return only part of a flow, so the loop mirrors what a real reader does.
func readFullMultiBuffer(t *testing.T, reader *pipe.Reader, want int) []byte {
	t.Helper()
	merged := make([]byte, 0, want)
	deadline := time.Now().Add(20 * time.Second)
	for len(merged) < want {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("timeout after %d of %d bytes", len(merged), want)
		}
		got, err := reader.ReadMultiBufferTimeout(remaining)
		if err != nil {
			t.Fatalf("read after %d of %d bytes: %v", len(merged), want, err)
		}
		for _, part := range got {
			merged = append(merged, part.Bytes()...)
		}
		buf.ReleaseMulti(got)
	}
	return merged
}

// startTaggedTCPEcho is an echo server whose reply carries tag, so a caller can
// tell which of two instances served a flow.
func startTaggedTCPEcho(t *testing.T, tag string) int {
	t.Helper()
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c stdnet.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte(tag))
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().(*stdnet.TCPAddr).Port
}
