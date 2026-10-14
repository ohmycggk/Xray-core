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

func TestStackFromALPN(t *testing.T) {
	for _, alpn := range []string{"", "nw3"} {
		if stack := StackFromALPN(alpn); stack != StackNw3 {
			t.Fatalf("alpn %q -> %d", alpn, stack)
		}
	}
	for _, alpn := range []string{"nw2", "custom-alpn"} {
		if stack := StackFromALPN(alpn); stack != StackNw2 {
			t.Fatalf("alpn %q -> %d", alpn, stack)
		}
	}
}

func TestResolveNowhereMorph(t *testing.T) {
	if resolveNowhereMorph(nil, StackNw2) {
		t.Fatal("nw2 must default morph off")
	}
	if !resolveNowhereMorph(nil, StackNw3) {
		t.Fatal("nw3 must default morph on")
	}
	on, off := true, false
	if !resolveNowhereMorph(&on, StackNw2) {
		t.Fatal("explicit on must win")
	}
	if resolveNowhereMorph(&off, StackNw3) {
		t.Fatal("explicit off must win")
	}
}

func TestNowhereV3Net(t *testing.T) {
	for _, testCase := range []struct {
		raw string
		net string
	}{
		{"", nowhereV3NetTCP},
		{"tcp", nowhereV3NetTCP},
		{"udp", nowhereV3NetUDP},
	} {
		net, err := nowhereV3Net(testCase.raw)
		if err != nil {
			t.Fatal(err)
		}
		if net != testCase.net {
			t.Fatalf("net %q -> %q", testCase.raw, net)
		}
	}
	if _, err := nowhereV3Net("ws"); err == nil {
		t.Fatal("expected net rejection")
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

// TestValidateNowhereNw2Endpoint covers the reverse direction: net belongs to
// the Nowhere 3 stack and must be rejected on a legacy nw2 endpoint.
func TestValidateNowhereNw2Endpoint(t *testing.T) {
	if err := validateNowhereNw2Endpoint(&Endpoint{Address: "127.0.0.1", Port: 443, Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	for _, net := range []string{"tcp", "udp", "quic"} {
		if err := validateNowhereNw2Endpoint(&Endpoint{Net: net}); err == nil {
			t.Fatalf("net %q accepted on nw2", net)
		}
	}
}

func TestValidateNowhereV3Server(t *testing.T) {
	if err := validateNowhereV3Server(&ServerConfig{Password: testNw3Key}); err != nil {
		t.Fatal(err)
	}
	if err := validateNowhereV3Server(&ServerConfig{Next: &Endpoint{}}); err == nil {
		t.Fatal("expected next chaining rejection")
	}
}

// TestValidateNowhereNw2Server covers the reverse direction: net and egress
// belong to the Nowhere 3 stack and must be rejected on a legacy nw2 Portal.
func TestValidateNowhereNw2Server(t *testing.T) {
	if err := validateNowhereNw2Server(&ServerConfig{Password: testNw3Key}); err != nil {
		t.Fatal(err)
	}
	if err := validateNowhereNw2Server(&ServerConfig{Net: "udp"}); err == nil {
		t.Fatal("expected net rejection")
	}
	if err := validateNowhereNw2Server(&ServerConfig{Egress: true}); err == nil {
		t.Fatal("expected egress rejection")
	}
}

func TestValidateNowhereV3Networks(t *testing.T) {
	for _, testCase := range []struct {
		networks []string
		net      string
	}{
		{nil, nowhereV3NetTCP},
		{[]string{"tcp"}, nowhereV3NetTCP},
		{[]string{"udp"}, nowhereV3NetUDP},
	} {
		if err := validateNowhereV3Networks(testCase.networks, testCase.net); err != nil {
			t.Fatalf("networks %v net %s: %v", testCase.networks, testCase.net, err)
		}
	}
	for _, testCase := range []struct {
		networks []string
		net      string
	}{
		{[]string{"udp"}, nowhereV3NetTCP},
		{[]string{"tcp"}, nowhereV3NetUDP},
		{[]string{"tcp", "udp"}, nowhereV3NetTCP},
	} {
		if err := validateNowhereV3Networks(testCase.networks, testCase.net); err == nil {
			t.Fatalf("networks %v net %s accepted", testCase.networks, testCase.net)
		}
	}
}

// TestNewServerV3RejectsUnsupportedFields drives the Nowhere 3 constructor
// directly so every rejection path is covered without a running Portal.
func TestNewServerV3RejectsUnsupportedFields(t *testing.T) {
	ctx := newNw3TestContext(t)
	base := func() *ServerConfig {
		return &ServerConfig{Password: testNw3Key}
	}
	for name, mutate := range map[string]func(*ServerConfig){
		"net":           func(c *ServerConfig) { c.Net = "ws" },
		"key":           func(c *ServerConfig) { c.Password = "xyz" },
		"key-length":    func(c *ServerConfig) { c.Password = testNw3Key + "01234567" },
		"missing-key":   func(c *ServerConfig) { c.Password = "" },
		"next":          func(c *ServerConfig) { c.Next = &Endpoint{} },
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
		}}
	}
	for name, mutate := range map[string]func(*ClientConfig){
		"net":        func(c *ClientConfig) { c.Endpoint.Net = "ws" },
		"password":   func(c *ClientConfig) { c.Endpoint.Password = "" },
		"key":        func(c *ClientConfig) { c.Endpoint.Password = "xyz" },
		"key-length": func(c *ClientConfig) { c.Endpoint.Password = testNw3Key + "01234567" },
		"up":         func(c *ClientConfig) { c.Endpoint.Up = "tcp" },
		"down":       func(c *ClientConfig) { c.Endpoint.Down = "tcp" },
		"mux":        func(c *ClientConfig) { c.Endpoint.Mux = true },
		"pool":       func(c *ClientConfig) { c.Endpoint.Pool = 4 },
		"alpn-nw2":   func(c *ClientConfig) { c.Endpoint.Alpn = "nw2" },
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
// ALPN to its own stack, that nw3 is the default, and that the nw2-only fields
// are rejected on whichever stack does not own them.
func TestNowhereDispatchSelectsStack(t *testing.T) {
	ctx := newNw3TestContext(t)
	// An omitted ALPN and an explicit nw3 ALPN both select Nowhere 3.
	for name, config := range map[string]*ServerConfig{
		"default":  {Password: testNw3Key},
		"explicit": {Password: testNw3Key, Alpn: "nw3"},
	} {
		t.Run("server-"+name, func(t *testing.T) {
			server, err := NewServer(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := server.(*ServerV3); !ok {
				t.Fatalf("%s server is %T", name, server)
			}
		})
	}
	// nw2 and a custom ALPN both keep the legacy Nowhere 2 stack.
	for name, config := range map[string]*ServerConfig{
		"nw2":    {Password: "0123456789abcdef0123456789abcdef", Alpn: "nw2"},
		"custom": {Password: "0123456789abcdef0123456789abcdef", Alpn: "custom-alpn"},
	} {
		t.Run("server-"+name, func(t *testing.T) {
			legacy, err := NewServer(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := legacy.(*Server); !ok {
				t.Fatalf("%s server is %T", name, legacy)
			}
		})
	}

	for name, endpoint := range map[string]*Endpoint{
		"default":  {Address: "127.0.0.1", Port: 443, Password: testNw3Key, AllowInsecure: true},
		"explicit": {Address: "127.0.0.1", Port: 443, Password: testNw3Key, AllowInsecure: true, Alpn: "nw3"},
	} {
		t.Run("client-"+name, func(t *testing.T) {
			client, err := NewClient(ctx, &ClientConfig{Endpoint: endpoint})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := client.(*ClientV3); !ok {
				t.Fatalf("%s client is %T", name, client)
			}
		})
	}
	for name, endpoint := range map[string]*Endpoint{
		"nw2":    {Address: "127.0.0.1", Port: 443, Password: "secret", AllowInsecure: true, Alpn: "nw2"},
		"custom": {Address: "127.0.0.1", Port: 443, Password: "secret", AllowInsecure: true, Alpn: "custom-alpn"},
	} {
		t.Run("client-"+name, func(t *testing.T) {
			legacyClient, err := NewClient(ctx, &ClientConfig{Endpoint: endpoint})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := legacyClient.(*Client); !ok {
				t.Fatalf("%s client is %T", name, legacyClient)
			}
		})
	}

	// Nowhere 3-only fields are rejected on the legacy nw2 stack.
	if _, err := NewServer(ctx, &ServerConfig{Password: "0123456789abcdef0123456789abcdef", Alpn: "nw2", Net: "udp"}); err == nil {
		t.Fatal("expected net rejection on nw2")
	}
	if _, err := NewServer(ctx, &ServerConfig{Password: "0123456789abcdef0123456789abcdef", Alpn: "nw2", Egress: true}); err == nil {
		t.Fatal("expected egress rejection on nw2")
	}
	if _, err := NewClient(ctx, &ClientConfig{Endpoint: &Endpoint{
		Address: "127.0.0.1", Port: 443, Password: "secret", AllowInsecure: true, Alpn: "nw2", Net: "udp",
	}}); err == nil {
		t.Fatal("expected net rejection on nw2")
	}
	// Nowhere 2-only fields are rejected on the nw3 stack.
	if _, err := NewServer(ctx, &ServerConfig{Password: testNw3Key, Next: &Endpoint{}}); err == nil {
		t.Fatal("expected next chaining rejection on nw3")
	}
	if _, err := NewClient(ctx, &ClientConfig{Endpoint: &Endpoint{
		Address: "127.0.0.1", Port: 443, Password: testNw3Key, AllowInsecure: true, Up: "tcp",
	}}); err == nil {
		t.Fatal("expected up rejection on nw3")
	}
}

// TestNowhereV3TCPForwarding runs a full Nowhere 3 endpoint pair over the TCP
// transport with Morph on (the nw3 default): the vendored Portal hands every
// authenticated flow to the Xray dispatcher, which serves it from the local
// freedom outbound. TCP flows and UDP flows carried as UoT both round-trip.
func TestNowhereV3TCPForwarding(t *testing.T) {
	echoPort := startTCPEcho(t)
	udpPort := startUDPEcho(t)
	serverPort := freePort(t)
	startV3Portal(t, serverPort, testNw3Key, nowhereV3NetTCP, nil, false, nil)
	handler := startV3Client(t, serverPort, testNw3Key, nowhereV3NetTCP, nil)

	assertV3TCP(t, handler, echoPort)
	assertV3UDP(t, handler, udpPort)
}

// TestNowhereV3MorphOff runs the same pair with Morph explicitly disabled on
// both ends, so both transform settings interoperate on the TCP transport.
func TestNowhereV3MorphOff(t *testing.T) {
	echoPort := startTCPEcho(t)
	serverPort := freePort(t)
	off := false
	startV3Portal(t, serverPort, testNw3Key, nowhereV3NetTCP, &off, false, nil)
	handler := startV3Client(t, serverPort, testNw3Key, nowhereV3NetTCP, &off)
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
func startV3Portal(t *testing.T, port int, password, net string, morph *bool, egress bool, networks []string) {
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
				Net:      net,
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
func startV3Client(t *testing.T, port int, password, net string, morph *bool) outbound.Handler {
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
				Net:           net,
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
