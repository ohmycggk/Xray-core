package morph

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/nowhere/internal/chacha20"
)

func TestDeriveMatchesRustFixedVectors(t *testing.T) {
	keys := Derive([]byte("test portal key"))
	wantC2S, _ := hex.DecodeString("90df47db82553ab6b0489ea77a085593475a70c6a61e957ad3ffe0824bd2126a")
	wantS2C, _ := hex.DecodeString("20bc17a22d08469e60efd4c6bdda76f190c33946599a0797bab2d52007b97e27")
	wantUDP, _ := hex.DecodeString("484b5f06a66e566099da4886e3bb2ec342aedee0ebcd7ea426d68ece4f3f8ea2")
	if !bytes.Equal(keys.TCPC2S[:], wantC2S) {
		t.Fatalf("tcp c2s\n got %x\nwant %x", keys.TCPC2S[:], wantC2S)
	}
	if !bytes.Equal(keys.TCPS2C[:], wantS2C) {
		t.Fatalf("tcp s2c\n got %x\nwant %x", keys.TCPS2C[:], wantS2C)
	}
	if !bytes.Equal(keys.UDP[:], wantUDP) {
		t.Fatalf("udp\n got %x\nwant %x", keys.UDP[:], wantUDP)
	}
}

func TestChaCha20RoundTripAtOffset(t *testing.T) {
	var key [32]byte
	var nonce [12]byte
	for i := range key {
		key[i] = byte(i)
	}
	plain := bytes.Repeat([]byte("sunscreen"), 20)
	out := append([]byte(nil), plain...)
	chacha20.XORKeyStreamAt(out, out, &key, &nonce, 64)
	if bytes.Equal(out, plain) {
		t.Fatal("keystream did not change plaintext")
	}
	chacha20.XORKeyStreamAt(out, out, &key, &nonce, 64)
	if !bytes.Equal(out, plain) {
		t.Fatal("xor not involutive")
	}
}

func TestTCPRoundTrip(t *testing.T) {
	keys := Derive([]byte("secret"))
	left, right := net.Pipe()
	client, err := WrapTCPClient(left, keys)
	if err != nil {
		t.Fatal(err)
	}
	server := WrapTCPServer(right, keys)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	payload := bytes.Repeat([]byte("nw2-morph"), 40)
	deadline := time.Now().Add(2 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)

	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		errCh <- err
	}()
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatal("server read mismatch")
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	go func() {
		_, err := server.Write(payload)
		errCh <- err
	}()
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatal("client read mismatch")
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}
