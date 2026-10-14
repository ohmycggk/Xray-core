package nowhere

import (
	"context"
	"crypto/tls"
	goerrors "errors"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/nowhere/core/egress"
	"github.com/xtls/xray-core/proxy/nowhere/core/morph"
	"github.com/xtls/xray-core/proxy/nowhere/core/qio"
	"github.com/xtls/xray-core/proxy/nowhere/core/wire"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// nowhereEgressReconnectDelay matches the reference CLI: a dropped
// registration waits three seconds before the host dials the Portal again.
const nowhereEgressReconnectDelay = 3 * time.Second

// EgressServer is the Nowhere 3 Egress client. It never listens: it dials the
// Portal over QUIC, registers as the Portal's single exit, and serves the flows
// the Portal opens through the Xray dispatcher. A second Egress is rejected by
// the Portal (ErrBusy) and keeps retrying without preempting the current owner.
type EgressServer struct {
	config *EgressConfig
	ctx    context.Context

	dialQUIC func(ctx context.Context) (qio.Conn, error)
	upstream *nw3Upstream

	runCtx    context.Context
	cancelRun context.CancelFunc
	done      chan struct{}

	closeOnce sync.Once
}

// NewEgressServer builds the Nowhere 3 Egress inbound.
func NewEgressServer(ctx context.Context, config *EgressConfig) (*EgressServer, error) {
	if config == nil || config.GetPassword() == "" {
		return nil, errors.New("nowhere: missing password")
	}
	if err := wire.ValidateServiceKey(config.GetPassword()); err != nil {
		return nil, errors.New("nowhere: egress key").Base(err)
	}
	if config.GetAddress() == "" || config.GetPort() == 0 {
		return nil, errors.New("nowhere: missing server")
	}
	v := core.MustFromContext(ctx)
	raw := v.GetFeature(routing.DispatcherType())
	dispatcher, _ := raw.(routing.Dispatcher)
	if dispatcher == nil {
		return nil, errors.New("nowhere: dispatcher is not available")
	}
	tag := ""
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		tag = inbound.Tag
	}
	// The Portal connection itself uses the system-selected source address; the
	// exit dials toward targets stay with the dispatcher.
	tlsConfig, err := buildNowhereV3EgressTLS(config)
	if err != nil {
		return nil, err
	}
	morphOn := resolveNowhereMorph(config.Morph, nowhereVersion3)
	var morphKeys *morph.Keys
	if morphOn {
		keys := nowhereV3MorphKeys(config.GetPassword())
		morphKeys = &keys
	}
	endpoint := &Endpoint{
		Address: config.GetAddress(),
		Port:    config.GetPort(),
	}
	carrierDialer := xrayDialer{system: true}
	dialQUIC := func(dialCtx context.Context) (qio.Conn, error) {
		return dialNowhereV3QUICCarrier(dialCtx, carrierDialer.DialPacket, endpoint.hostport(), tlsConfig, morphKeys)
	}
	return &EgressServer{
		config:   config,
		ctx:      ctx,
		dialQUIC: dialQUIC,
		upstream: &nw3Upstream{dispatcher: dispatcher, tag: tag},
	}, nil
}

func (s *EgressServer) Network() []xnet.Network { return nil }

func (s *EgressServer) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	return errors.New("nowhere: egress does not accept inbound connections")
}

// Start launches the registration loop. The loop owns one registration at a
// time: egress.Run dials the Portal, registers, and serves flows until the
// connection drops. Every drop returns here, waits out the cooldown, and dials
// again, so a restarted Portal or a stolen exit is picked up without operator
// action.
func (s *EgressServer) Start() error {
	if s.cancelRun != nil {
		return nil
	}
	s.runCtx, s.cancelRun = context.WithCancel(s.ctx)
	s.done = make(chan struct{})
	go s.run(s.runCtx)
	return nil
}

func (s *EgressServer) run(ctx context.Context) {
	defer close(s.done)
	for {
		err := egress.Run(ctx, egress.Config{
			SharedKey: s.config.GetPassword(),
			DialQUIC:  s.dialQUIC,
			Upstream:  s.upstream,
		})
		if ctx.Err() != nil {
			return
		}
		switch {
		case goerrors.Is(err, egress.ErrBusy):
			errors.LogWarning(context.Background(), "nowhere egress: portal already has an exit registered; retrying")
		case err != nil:
			errors.LogWarning(context.Background(), "nowhere egress: registration dropped: ", err)
		default:
			errors.LogWarning(context.Background(), "nowhere egress: registration closed; reconnecting")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(nowhereEgressReconnectDelay):
		}
	}
}

func (s *EgressServer) Close() error {
	s.closeOnce.Do(func() {
		if s.cancelRun != nil {
			s.cancelRun()
		}
		if s.done != nil {
			<-s.done
		}
	})
	return nil
}

var (
	_ common.Runnable = (*EgressServer)(nil)
	_ common.Closable = (*EgressServer)(nil)
)

func init() {
	common.Must(common.RegisterConfig((*EgressConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewEgressServer(ctx, config.(*EgressConfig))
	}))
}

// buildNowhereV3EgressTLS produces the client config the Egress uses for its
// Portal connection: TLS 1.3, ALPN nw3, and the same trust rules as the Vector.
func buildNowhereV3EgressTLS(config *EgressConfig) (*tls.Config, error) {
	ep := &Endpoint{
		Address:       config.GetAddress(),
		Port:          config.GetPort(),
		ServerName:    config.GetServerName(),
		Pin:           config.GetPin(),
		AllowInsecure: config.GetAllowInsecure(),
	}
	return buildNowhereV3ClientTLS(ep)
}
