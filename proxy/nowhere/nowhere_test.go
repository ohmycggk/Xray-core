package nowhere

import (
	"bytes"
	"context"
	"fmt"
	"io"
	stdnet "net"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/nowhere/bundle"
	"github.com/xtls/xray-core/proxy/nowhere/wire"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"

	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/udp"
)

func TestNowhereCarriers(t *testing.T) {
	echoPort := startTCPEcho(t)
	udpPort := startUDPEcho(t)
	serverPort := freePort(t)
	startPortal(t, serverPort, "shared-secret", []string{"tcp", "udp"}, false, nil)

	cases := []struct {
		name string
		up   string
		down string
		mux  bool
		udp  bool
	}{
		{name: "tcp", up: "tcp", down: "tcp"},
		{name: "mux", up: "tcp", down: "tcp", mux: true},
		{name: "quic", up: "udp", down: "udp"},
		{name: "quic-udp", up: "udp", down: "udp", udp: true},
		{name: "split-tcp-udp", up: "tcp", down: "udp"},
		{name: "split-udp-tcp", up: "udp", down: "tcp", udp: true},
		{name: "mix", up: "mix", down: "mix"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flow := testBundle(t, serverPort, "shared-secret", tc.up, tc.down, tc.mux, false)
			if tc.udp {
				assertUDP(t, flow, udpPort)
			} else {
				assertTCP(t, flow, echoPort)
			}
		})
	}
}

func TestNowhereMorph(t *testing.T) {
	echoPort := startTCPEcho(t)
	udpPort := startUDPEcho(t)
	serverPort := freePort(t)
	startPortal(t, serverPort, "morph-secret", []string{"tcp", "udp"}, true, nil)

	t.Run("tcp", func(t *testing.T) {
		flow := testBundle(t, serverPort, "morph-secret", "tcp", "tcp", false, true)
		assertTCP(t, flow, echoPort)
	})
	t.Run("quic-udp", func(t *testing.T) {
		flow := testBundle(t, serverPort, "morph-secret", "udp", "udp", false, true)
		assertUDP(t, flow, udpPort)
	})
}

func TestNowherePortalNext(t *testing.T) {
	echoPort := startTCPEcho(t)
	origin := freePort(t)
	startPortal(t, origin, "origin-secret", []string{"tcp"}, false, nil)
	chain := freePort(t)
	startPortal(t, chain, "chain-secret", []string{"tcp"}, false, &Endpoint{
		Address:       "127.0.0.1",
		Port:          uint32(origin),
		Password:      "origin-secret",
		Up:            "tcp",
		Down:          "tcp",
		AllowInsecure: true,
	})
	flow := testBundle(t, chain, "chain-secret", "tcp", "tcp", false, false)
	assertTCP(t, flow, echoPort)
}

func TestNowhereXrayOutbound(t *testing.T) {
	echoPort := startTCPEcho(t)
	serverPort := freePort(t)
	startPortal(t, serverPort, "outbound-secret", []string{"tcp", "udp"}, false, nil)

	clientPort := freePort(t)
	client, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&policy.Config{}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			Tag: "in",
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(net.Port(clientPort))}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  net.NewIPOrDomain(net.LocalHostIP),
				RewritePort:     uint32(echoPort),
				AllowedNetworks: []net.Network{net.Network_TCP},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: "nw",
			ProxySettings: serial.ToTypedMessage(&ClientConfig{Endpoint: &Endpoint{
				Address:       "127.0.0.1",
				Port:          uint32(serverPort),
				Password:      "outbound-secret",
				Up:            "tcp",
				Down:          "tcp",
				AllowInsecure: true,
			}}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	conn, err := stdnet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("xray-outbound-nowhere")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q", got)
	}
}

func TestNowhereXrayOutboundUDP(t *testing.T) {
	udpPort := startUDPEcho(t)
	serverPort := freePort(t)
	startPortal(t, serverPort, "udp-outbound", []string{"udp"}, false, nil)

	client, err := core.New(&core.Config{
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
				Port:          uint32(serverPort),
				Password:      "udp-outbound",
				Up:            "udp",
				Down:          "udp",
				AllowInsecure: true,
			}}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	handler := client.GetFeature(outbound.ManagerType()).(outbound.Manager).GetHandler("nw")
	if handler == nil {
		t.Fatal("missing nowhere outbound")
	}
	dest := net.UDPDestination(net.LocalHostIP, net.Port(udpPort))
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: dest}})
	uplinkReader, uplinkWriter := pipe.New()
	downlinkReader, downlinkWriter := pipe.New()
	go handler.Dispatch(ctx, &transport.Link{Reader: uplinkReader, Writer: downlinkWriter})

	payload := bytes.Repeat([]byte("U"), 1800)
	packet := buf.New()
	packet.Write(payload)
	if err := uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
		t.Fatal(err)
	}
	got, err := downlinkReader.ReadMultiBufferTimeout(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	merged := make([]byte, 0, got.Len())
	for _, part := range got {
		merged = append(merged, part.Bytes()...)
	}
	buf.ReleaseMulti(got)
	if !bytes.Equal(merged, payload) {
		t.Fatalf("udp outbound payload mismatch: %d bytes", len(merged))
	}
}

func TestNowhereRejectsBadPassword(t *testing.T) {
	serverPort := freePort(t)
	startPortal(t, serverPort, "right-secret", []string{"tcp"}, false, nil)
	flow := testBundle(t, serverPort, "wrong-secret", "tcp", "tcp", false, false)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	target, err := wire.NewIPTarget(netip.MustParseAddr("127.0.0.1"), 1)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := flow.OpenTCP(ctx, target)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected authentication failure")
	}
}

func startPortal(t *testing.T, port int, password string, networks []string, morph bool, next *Endpoint) {
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
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(net.Port(port))}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&ServerConfig{
				Password: password,
				Networks: networks,
				Morph:    morph,
				Next:     next,
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

type testPacketDialer struct{}

func (testPacketDialer) DialTCP(ctx context.Context, address string) (stdnet.Conn, error) {
	var dialer stdnet.Dialer
	return dialer.DialContext(ctx, "tcp", address)
}

func (testPacketDialer) DialPacket(ctx context.Context, address string) (stdnet.PacketConn, stdnet.Addr, error) {
	pc, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	remote, err := stdnet.ResolveUDPAddr("udp", address)
	if err != nil {
		_ = pc.Close()
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = pc.Close()
		return nil, nil, err
	}
	return pc, remote, nil
}

func testBundle(t *testing.T, port int, password, up, down string, mux, morph bool) *bundle.CarrierBundle {
	t.Helper()
	flow, err := openBundle(&Endpoint{
		Address:       "127.0.0.1",
		Port:          uint32(port),
		Password:      password,
		Up:            up,
		Down:          down,
		Mux:           mux,
		Morph:         morph,
		AllowInsecure: true,
	}, testPacketDialer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = flow.Close() })
	return flow
}

func assertTCP(t *testing.T, flow *bundle.CarrierBundle, port int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target, err := wire.NewIPTarget(netip.MustParseAddr("127.0.0.1"), uint16(port))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := flow.OpenTCP(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte("nw"), 2048)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("tcp payload mismatch")
	}
}

func assertUDP(t *testing.T, flow *bundle.CarrierBundle, port int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target, err := wire.NewIPTarget(netip.MustParseAddr("127.0.0.1"), uint16(port))
	if err != nil {
		t.Fatal(err)
	}
	pc, err := flow.OpenUDP(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	payload := bytes.Repeat([]byte("u"), 2000)
	addr := &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1"), Port: port}
	if _, err := pc.WriteTo(payload, addr); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, 65535)
	n, _, err := pc.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], payload) {
		t.Fatalf("udp payload mismatch: got %d bytes", n)
	}
}

func startTCPEcho(t *testing.T) int {
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
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().(*stdnet.TCPAddr).Port
}

func startUDPEcho(t *testing.T) int {
	t.Helper()
	pc, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().(*stdnet.UDPAddr).Port
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*stdnet.TCPAddr).Port
	_ = ln.Close()
	return port
}
