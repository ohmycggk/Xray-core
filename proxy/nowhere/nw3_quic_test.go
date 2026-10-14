package nowhere

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
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

// TestNowhereV3QUICForwarding runs a full Nowhere 3 endpoint pair over the UDP
// transport with Morph on (the nw3 default): the Portal serves a sealed UDP
// socket below QUIC, and both TCP flows and UDP datagrams reach the echo target.
func TestNowhereV3QUICForwarding(t *testing.T) {
	echoPort := startTCPEcho(t)
	udpPort := startUDPEcho(t)
	serverPort := freePort(t)
	startV3Portal(t, serverPort, testNw3Key, nowhereV3NetUDP, nil, false, []string{"udp"})
	handler := startV3Client(t, serverPort, testNw3Key, nowhereV3NetUDP, nil)

	assertV3TCP(t, handler, echoPort)
	assertV3UDP(t, handler, udpPort)
}

// TestNowhereV3EgressRegistration covers the exit bridge: a Portal in egress
// mode forwards authenticated flows to the single registered Egress client, a
// second Egress is told the exit is busy and keeps retrying without preempting
// the owner, and after the owner drops the waiting Egress takes over.
//
// Each Egress runs in its own Xray instance whose direct outbound overrides the
// destination to its own tagged echo, so the reply of a flow names the exit that
// served it.
func TestNowhereV3EgressRegistration(t *testing.T) {
	primaryEcho := startTaggedTCPEcho(t, "primary")
	secondaryEcho := startTaggedTCPEcho(t, "secondary")
	serverPort := freePort(t)
	startV3Portal(t, serverPort, testNw3Key, nowhereV3NetUDP, nil, true, []string{"udp"})
	handler := startV3Client(t, serverPort, testNw3Key, nowhereV3NetUDP, nil)

	primary := startV3Egress(t, serverPort, primaryEcho)
	// Registration has no success signal, so poll the data path.
	waitForV3Egress(t, handler, "primary")

	secondary := startV3Egress(t, serverPort, secondaryEcho)
	// Give the challenger more than two reconnect cycles, then prove the owner
	// still serves every flow and the challenger never routed anything.
	time.Sleep(2*nowhereEgressReconnectDelay + time.Second)
	waitForV3Egress(t, handler, "primary")

	// Dropping the owner releases the exit; the waiting Egress reconnects and
	// takes over within one cooldown.
	_ = primary.Close()
	waitForV3Egress(t, handler, "secondary")
	_ = secondary.Close()
}

// waitForV3Egress polls a TCP flow until the reply carries tag, proving the
// named Egress owns the Portal.
func waitForV3Egress(t *testing.T, handler outbound.Handler, tag string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if got := v3EgressFlow(t, handler); got == tag {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("egress %q did not take over the portal", tag)
}

// v3EgressFlow runs one TCP flow and returns the tag of the Egress that served
// it, or an empty string when the flow failed.
func v3EgressFlow(t *testing.T, handler outbound.Handler) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dest := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(1))
	uplinkReader, uplinkWriter := pipe.New()
	downlinkReader, downlinkWriter := pipe.New()
	go handler.Dispatch(session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}}), &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	})

	payload := []byte("nw3-egress")
	packet := buf.New()
	packet.Write(payload)
	if err := uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
		return ""
	}
	got, err := downlinkReader.ReadMultiBufferTimeout(3 * time.Second)
	if err != nil {
		_ = uplinkWriter.Close()
		_ = downlinkWriter.Close()
		return ""
	}
	merged := make([]byte, 0, got.Len())
	for _, part := range got {
		merged = append(merged, part.Bytes()...)
	}
	buf.ReleaseMulti(got)
	_ = uplinkWriter.Close()
	_ = downlinkWriter.Close()
	if !bytes.HasSuffix(merged, payload) {
		return ""
	}
	return string(merged[:len(merged)-len(payload)])
}

// startV3Egress brings up a Nowhere 3 Egress inbound that dials the Portal on
// portalPort and serves its flows from a direct outbound pinned to echoPort.
func startV3Egress(t *testing.T, portalPort, echoPort int) *core.Instance {
	t.Helper()
	inst, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&policy.Config{}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			Tag: "nowhere-egress",
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(freePort(t)))}},
				Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&EgressConfig{
				Address:       "127.0.0.1",
				Port:          uint32(portalPort),
				Password:      testNw3Key,
				AllowInsecure: true,
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: "direct",
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				DestinationOverride: &freedom.DestinationOverride{
					Server: &protocol.ServerEndpoint{
						Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
						Port:    uint32(echoPort),
					},
				},
			}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	return inst
}
