package nowhere

import (
	"context"
	stdnet "net"
	"strconv"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/nowhere/bundle"
	"github.com/xtls/xray-core/proxy/nowhere/wire"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Client is a Nowhere outbound. One bundle is shared by every flow so QUIC
// sessions, mux shards, and the TCP pool stay warm.
type Client struct {
	config    *ClientConfig
	policy    policy.Manager
	userLevel uint32
	sockopt   *internet.SocketConfig

	mu     sync.Mutex
	bundle *bundle.CarrierBundle
	closed bool
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config == nil || config.Endpoint == nil {
		return nil, errors.New("nowhere: missing server")
	}
	if err := config.Endpoint.validate(); err != nil {
		return nil, err
	}
	stream, err := validateRawStream(ctx)
	if err != nil {
		return nil, err
	}
	v := core.MustFromContext(ctx)
	manager := v.GetFeature(policy.ManagerType()).(policy.Manager)
	var sockopt *internet.SocketConfig
	if stream != nil {
		sockopt = stream.SocketSettings
	}
	return &Client{
		config:    config,
		policy:    manager,
		userLevel: config.UserLevel,
		sockopt:   sockopt,
	}, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return errors.New("nowhere: target is not specified")
	}
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("nowhere: target is not specified")
	}
	ob.Name = "nowhere"
	ob.CanSpliceCopy = 3
	target, err := wireTarget(ob.Target)
	if err != nil {
		return err
	}
	flow, err := c.ensure(dialer)
	if err != nil {
		return err
	}
	timeouts := c.policy.ForLevel(c.userLevel).Timeouts
	if ob.Target.Network == xnet.Network_UDP {
		return c.processUDP(ctx, flow, target, ob.Target, link, timeouts)
	}
	return c.processTCP(ctx, flow, target, link, timeouts)
}

func (c *Client) processTCP(ctx context.Context, flow *bundle.CarrierBundle, target wire.Target, link *transport.Link, timeouts policy.Timeout) error {
	conn, err := flow.OpenTCP(ctx, target)
	if err != nil {
		return errors.New("nowhere: failed to open tcp flow").Base(err)
	}
	defer conn.Close()
	errors.LogInfo(ctx, "nowhere tunneling tcp to ", targetText(target))
	return relay(ctx, timeouts, link.Reader, buf.NewWriter(conn), &buf.TimeoutWrapperReader{Reader: buf.NewReader(conn)}, link.Writer, func() {
		if half, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
	})
}

func (c *Client) processUDP(ctx context.Context, flow *bundle.CarrierBundle, target wire.Target, dest xnet.Destination, link *transport.Link, timeouts policy.Timeout) error {
	pc, err := flow.OpenUDP(ctx, target)
	if err != nil {
		return errors.New("nowhere: failed to open udp flow").Base(err)
	}
	defer pc.Close()
	errors.LogInfo(ctx, "nowhere tunneling udp to ", targetText(target))
	return relay(ctx, timeouts, link.Reader, &packetWriter{pc: pc, addr: udpAddr(target)}, &buf.TimeoutWrapperReader{Reader: &packetReader{pc: pc, dest: dest}}, link.Writer, nil)
}

func targetText(target wire.Target) string {
	port := strconv.FormatUint(uint64(target.Port), 10)
	switch target.Type {
	case wire.TargetTypeDomain:
		return stdnet.JoinHostPort(target.Host, port)
	default:
		if target.Addr.IsValid() {
			return stdnet.JoinHostPort(target.Addr.String(), port)
		}
		return port
	}
}

func relay(ctx context.Context, timeouts policy.Timeout, uplink buf.Reader, uplinkWriter buf.Writer, downlink buf.Reader, downlinkWriter buf.Writer, onUplinkDone func()) error {
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, timeouts.ConnectionIdle)
	request := func() error {
		defer timer.SetTimeout(timeouts.DownlinkOnly)
		err := buf.Copy(uplink, uplinkWriter, buf.UpdateActivity(timer))
		if onUplinkDone != nil {
			onUplinkDone()
		}
		return err
	}
	response := func() error {
		defer timer.SetTimeout(timeouts.UplinkOnly)
		return buf.Copy(downlink, downlinkWriter, buf.UpdateActivity(timer))
	}
	if err := task.Run(ctx, request, task.OnSuccess(response, task.Close(downlinkWriter))); err != nil {
		return errors.New("nowhere connection ends").Base(err)
	}
	return nil
}

func (c *Client) ensure(dialer internet.Dialer) (*bundle.CarrierBundle, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("nowhere: outbound is closed")
	}
	if c.bundle != nil {
		return c.bundle, nil
	}
	flow, err := openBundle(c.config.Endpoint, xrayDialer{dialer: dialer, sockopt: c.sockopt})
	if err != nil {
		return nil, err
	}
	c.bundle = flow
	return flow, nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.bundle == nil {
		return nil
	}
	err := c.bundle.Close()
	c.bundle = nil
	return err
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

var _ stdnet.Conn = (*streamConn)(nil)
