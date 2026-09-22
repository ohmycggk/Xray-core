package nowhere

import (
	"context"
	goerrors "errors"
	"io"
	stdnet "net"
	"net/netip"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/nowhere/server"
	"github.com/xtls/xray-core/proxy/nowhere/wire"
	"github.com/xtls/xray-core/transport"
)

type dispatchUpstream struct {
	dispatcher routing.Dispatcher
	tag        string
	level      uint32
	sniff      session.SniffingRequest
}

func (u *dispatchUpstream) HandleStream(ctx context.Context, conn stdnet.Conn, source stdnet.Addr, target wire.Target, readiness server.FlowReadiness) error {
	dest, err := destinationFromTarget(target, xnet.Network_TCP)
	if err != nil {
		if readiness != nil {
			_ = readiness.Reject(err)
		}
		return err
	}
	if readiness != nil {
		if err = readiness.Ready(); err != nil {
			return err
		}
	}
	ctx = u.decorate(ctx, source, conn.LocalAddr())
	err = u.dispatcher.DispatchLink(ctx, dest, &transport.Link{
		Reader: &buf.TimeoutWrapperReader{Reader: buf.NewReader(conn)},
		Writer: buf.NewWriter(conn),
	})
	cause := err
	_ = conn.Close()
	if handler := server.CloseHandlerFromContext(ctx); handler != nil {
		handler(cause)
	}
	return ended(err)
}

func (u *dispatchUpstream) HandlePacket(ctx context.Context, pc stdnet.PacketConn, source stdnet.Addr, target wire.Target, readiness server.FlowReadiness) error {
	dest, err := destinationFromTarget(target, xnet.Network_UDP)
	if err != nil {
		if readiness != nil {
			_ = readiness.Reject(err)
		}
		return err
	}
	if readiness != nil {
		if err = readiness.Ready(); err != nil {
			return err
		}
	}
	ctx = u.decorate(ctx, source, pc.LocalAddr())
	err = u.dispatcher.DispatchLink(ctx, dest, &transport.Link{
		Reader: &buf.TimeoutWrapperReader{Reader: &packetReader{pc: pc, dest: dest}},
		Writer: &packetWriter{pc: pc, addr: udpAddr(target)},
	})
	cause := err
	_ = pc.Close()
	if handler := server.CloseHandlerFromContext(ctx); handler != nil {
		handler(cause)
	}
	return ended(err)
}

func (u *dispatchUpstream) decorate(ctx context.Context, source, local stdnet.Addr) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	var inbound session.Inbound
	if existing := session.InboundFromContext(ctx); existing != nil {
		inbound = *existing
	}
	inbound.Name = "nowhere"
	inbound.CanSpliceCopy = 3
	if inbound.Tag == "" {
		inbound.Tag = u.tag
	}
	if inbound.User == nil {
		inbound.User = &protocol.MemoryUser{Level: u.level}
	}
	if dest, ok := destinationFromAddr(source); ok {
		inbound.Source = dest
	}
	if dest, ok := destinationFromAddr(local); ok {
		inbound.Local = dest
	}
	ctx = session.ContextWithInbound(ctx, &inbound)
	if session.ContentFromContext(ctx) == nil {
		ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: u.sniff})
	}
	if len(session.OutboundsFromContext(ctx)) == 0 {
		ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	}
	return ctx
}

func ended(err error) error {
	if err == nil || goerrors.Is(err, io.EOF) || goerrors.Is(err, stdnet.ErrClosed) || goerrors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func wireTarget(dest xnet.Destination) (wire.Target, error) {
	if !dest.IsValid() || dest.Address == nil || dest.Port == 0 {
		return wire.Target{}, errors.New("nowhere: target is not specified")
	}
	port := uint16(dest.Port)
	if dest.Address.Family().IsDomain() {
		return wire.NewDomainTarget(dest.Address.Domain(), port)
	}
	ip, ok := netip.AddrFromSlice(dest.Address.IP())
	if !ok {
		return wire.Target{}, errors.New("nowhere: invalid target address")
	}
	return wire.NewIPTarget(ip.Unmap(), port)
}

func destinationFromTarget(target wire.Target, network xnet.Network) (xnet.Destination, error) {
	switch target.Type {
	case wire.TargetTypeDomain:
		return xnet.Destination{Network: network, Address: xnet.DomainAddress(target.Host), Port: xnet.Port(target.Port)}, nil
	case wire.TargetTypeIPv4, wire.TargetTypeIPv6:
		if !target.Addr.IsValid() {
			return xnet.Destination{}, errors.New("nowhere: invalid target address")
		}
		return xnet.Destination{Network: network, Address: xnet.IPAddress(target.Addr.AsSlice()), Port: xnet.Port(target.Port)}, nil
	default:
		return xnet.Destination{}, errors.New("nowhere: unsupported target")
	}
}

func destinationFromAddr(addr stdnet.Addr) (xnet.Destination, bool) {
	switch a := addr.(type) {
	case *stdnet.TCPAddr:
		if len(a.IP) == 0 {
			return xnet.Destination{}, false
		}
		return xnet.TCPDestination(xnet.IPAddress(a.IP), xnet.Port(a.Port)), true
	case *stdnet.UDPAddr:
		if len(a.IP) == 0 {
			return xnet.Destination{}, false
		}
		return xnet.UDPDestination(xnet.IPAddress(a.IP), xnet.Port(a.Port)), true
	default:
		return xnet.Destination{}, false
	}
}

func udpAddr(target wire.Target) stdnet.Addr {
	if target.Addr.IsValid() {
		return &stdnet.UDPAddr{IP: target.Addr.AsSlice(), Port: int(target.Port)}
	}
	return &stdnet.UDPAddr{IP: stdnet.IPv4zero, Port: int(target.Port)}
}

type packetReader struct {
	pc   stdnet.PacketConn
	dest xnet.Destination
}

func (r *packetReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	raw := make([]byte, 65535)
	n, _, err := r.pc.ReadFrom(raw)
	if n == 0 && err != nil {
		return nil, err
	}
	payload := append([]byte(nil), raw[:n]...)
	buffer := buf.FromBytes(payload)
	dest := r.dest
	buffer.UDP = &dest
	if err != nil {
		return buf.MultiBuffer{buffer}, err
	}
	return buf.MultiBuffer{buffer}, nil
}

type packetWriter struct {
	pc   stdnet.PacketConn
	addr stdnet.Addr
}

func (w *packetWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, buffer := range mb {
		if buffer == nil {
			continue
		}
		if _, err := w.pc.WriteTo(buffer.Bytes(), w.addr); err != nil {
			return err
		}
	}
	return nil
}
