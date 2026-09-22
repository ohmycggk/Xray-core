// Package morph implements the Nowhere 2 keyed socket transform below TLS/QUIC.
package morph

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/xtls/xray-core/proxy/nowhere/internal/chacha20"
	"github.com/xtls/xray-core/proxy/nowhere/internal/hkdf"
)

const (
	nonceLen      = 12
	streamLimit   = (1 << 38) - 64
	udpKeyInfo    = "udp"
	tcpC2SInfo    = "tcp c2s"
	tcpS2CInfo    = "tcp s2c"
	morphRootSalt = "nowhere/morph"
)

// Keys are the Morph HKDF outputs for one hop. They must not be logged.
type Keys struct {
	TCPC2S [32]byte
	TCPS2C [32]byte
	UDP    [32]byte
}

// Derive builds Morph keys from the endpoint shared key.
func Derive(sharedKey []byte) Keys {
	root := hkdf.ExtractSHA256([]byte(morphRootSalt), sharedKey)
	var keys Keys
	hkdf.ExpandSHA256(root, []byte(tcpC2SInfo), keys.TCPC2S[:], sha256.New)
	hkdf.ExpandSHA256(root, []byte(tcpS2CInfo), keys.TCPS2C[:], sha256.New)
	hkdf.ExpandSHA256(root, []byte(udpKeyInfo), keys.UDP[:], sha256.New)
	return keys
}

// WrapTCPClient writes a 12-byte nonce then XOR-transforms TLS bytes.
func WrapTCPClient(conn net.Conn, keys Keys) (net.Conn, error) {
	var nonce [nonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	pref := make([]byte, nonceLen)
	copy(pref, nonce[:])
	return &tcpConn{
		Conn:      conn,
		readKey:   keys.TCPS2C,
		writeKey:  keys.TCPC2S,
		nonce:     nonce,
		writePref: pref,
	}, nil
}

// WrapTCPServer reads the client nonce then XOR-transforms TLS bytes.
func WrapTCPServer(conn net.Conn, keys Keys) net.Conn {
	return &tcpConn{
		Conn:     conn,
		readKey:  keys.TCPC2S,
		writeKey: keys.TCPS2C,
		readNeed: nonceLen,
	}
}

type tcpConn struct {
	net.Conn
	readKey, writeKey [32]byte
	nonce             [nonceLen]byte
	readOff, writeOff uint64
	writePref         []byte
	readNeed          int
	readMu, writeMu   sync.Mutex
}

func (c *tcpConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readNeed > 0 {
		buf := make([]byte, c.readNeed)
		if _, err := io.ReadFull(c.Conn, buf); err != nil {
			return 0, err
		}
		copy(c.nonce[nonceLen-c.readNeed:], buf)
		c.readNeed = 0
	}
	if len(p) == 0 {
		return 0, nil
	}
	if err := checkLimit(c.readOff, len(p)); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		chacha20.XORKeyStreamAt(p[:n], p[:n], &c.readKey, &c.nonce, c.readOff)
		c.readOff += uint64(n)
	}
	return n, err
}

func (c *tcpConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	if len(c.writePref) > 0 {
		n, err := c.Conn.Write(c.writePref)
		c.writePref = c.writePref[n:]
		if err != nil {
			return 0, err
		}
		if len(c.writePref) > 0 {
			return 0, io.ErrShortWrite
		}
	}
	if len(p) == 0 {
		return 0, nil
	}
	if err := checkLimit(c.writeOff, len(p)); err != nil {
		return 0, err
	}
	buf := append([]byte(nil), p...)
	chacha20.XORKeyStreamAt(buf, buf, &c.writeKey, &c.nonce, c.writeOff)
	n, err := c.Conn.Write(buf)
	c.writeOff += uint64(n)
	written += n
	return written, err
}

func checkLimit(offset uint64, n int) error {
	if n < 0 {
		return errors.New("nowhere: morph invalid length")
	}
	if offset+uint64(n) > streamLimit {
		return errors.New("nowhere: Morph TCP keystream exhausted")
	}
	return nil
}

// WrapPacketConn XOR-transforms every UDP datagram with a fresh 12-byte nonce.
func WrapPacketConn(pc net.PacketConn, key [32]byte) net.PacketConn {
	return &packetConn{PacketConn: pc, key: key}
}

type packetConn struct {
	net.PacketConn
	key [32]byte
	mu  sync.Mutex
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	var nonce [nonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return 0, err
	}
	buf := make([]byte, nonceLen+len(p))
	copy(buf, nonce[:])
	if len(p) > 0 {
		chacha20.XORKeyStreamAt(buf[nonceLen:], p, &c.key, &nonce, 0)
	}
	n, err := c.PacketConn.WriteTo(buf, addr)
	if n < nonceLen {
		return 0, err
	}
	return n - nonceLen, err
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	buf := make([]byte, nonceLen+len(p))
	n, addr, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	if n <= nonceLen {
		return 0, addr, nil
	}
	var nonce [nonceLen]byte
	copy(nonce[:], buf[:nonceLen])
	payload := buf[nonceLen:n]
	out := p
	if len(out) < len(payload) {
		payload = payload[:len(out)]
	}
	chacha20.XORKeyStreamAt(out, payload, &c.key, &nonce, 0)
	return len(payload), addr, nil
}

var (
	_ net.Conn       = (*tcpConn)(nil)
	_ net.PacketConn = (*packetConn)(nil)
)
