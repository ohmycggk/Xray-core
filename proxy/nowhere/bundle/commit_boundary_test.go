package bundle

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/xtls/xray-core/proxy/nowhere/wire"
)

// A flow that reached the commit stage must fail outright: there is no second
// route and no new flow ID once the FlowHeader has been written.
func TestUDPOpenDoesNotRetryAfterCommitStarts(t *testing.T) {
	tests := []struct {
		name string
		set  func(*testing.T, *v15AuthSession)
	}{
		{
			name: "flow header commit",
			set: func(_ *testing.T, raw *v15AuthSession) {
				raw.stream.commitErr = io.ErrClosedPipe
			},
		},
		{
			name: "non-ready setup result",
			set: func(t *testing.T, raw *v15AuthSession) {
				client, peer := net.Pipe()
				raw.stream.conn = client
				t.Cleanup(func() { _ = peer.Close() })
				go func() {
					_ = wire.WriteSetupResult(peer, wire.SetupResultDialFailed)
				}()
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := &v15AuthSession{}
			test.set(t, raw)
			credentials, err := wire.NewCredentials("commit-boundary")
			if err != nil {
				t.Fatal(err)
			}
			b := newV15QUICOnlyBundle(t, credentials, &v15AuthBackend{session: raw})
			defer b.Close()
			target, err := wire.NewDomainTarget("commit-boundary.example", 443)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.OpenUDP(context.Background(), target); err == nil {
				t.Fatal("expected committed flow failure")
			}
			if got := raw.prepareCalls; got != 1 {
				t.Fatalf("QUIC stream preparations = %d, want 1", got)
			}
			if got := b.nextFlowID.Load(); got != 2 {
				t.Fatalf("next flow ID = %d, a retry allocated another ID", got)
			}
		})
	}
}
