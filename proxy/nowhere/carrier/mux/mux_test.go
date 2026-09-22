package mux

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func startPair(t *testing.T) (*Handle, *Incoming, *Handle, *Incoming) {
	t.Helper()
	left, right := net.Pipe()
	client, clientIn, err := Start(left, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	server, serverIn, err := Start(right, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, clientIn, server, serverIn
}

func TestStreamRoundTripAndHalfClose(t *testing.T) {
	client, _, _, serverIn := startPair(t)
	outgoing, err := client.OpenStream(7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outgoing.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := outgoing.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	incoming, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(incoming)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("hello")) {
		t.Fatalf("got %q", payload)
	}
}

func TestIdleDeadlineResetsWhenStreamBecomesActive(t *testing.T) {
	client, _, _, serverIn := startPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	idleDone := make(chan bool, 1)
	go func() {
		idleDone <- client.IdleFor(ctx, 80*time.Millisecond)
	}()
	time.Sleep(40 * time.Millisecond)
	outgoing, err := client.OpenStream(1)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-idleDone:
		t.Fatal("idle completed while a stream was active")
	case <-time.After(50 * time.Millisecond):
	}
	_ = outgoing.Close()
	_ = accepted.Close()
	select {
	case idle := <-idleDone:
		if !idle {
			t.Fatal("expected idle after streams closed")
		}
	case <-time.After(400 * time.Millisecond):
		t.Fatal("idle did not complete")
	}
}

func TestManySmallWritesCrossCreditWindow(t *testing.T) {
	client, _, _, serverIn := startPair(t)
	outgoing, err := client.OpenStream(8)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accepted, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packet := bytes.Repeat([]byte{0x5a}, 1202)
	const count = 1024
	type readResult struct {
		got []byte
		err error
	}
	done := make(chan readResult, 1)
	go func() {
		got, err := io.ReadAll(io.LimitReader(accepted, int64(len(packet)*count)))
		done <- readResult{got: got, err: err}
	}()
	for i := 0; i < count; i++ {
		if _, err := outgoing.Write(packet); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := outgoing.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatal(res.err)
		}
		if len(res.got) != len(packet)*count {
			t.Fatalf("len=%d want %d", len(res.got), len(packet)*count)
		}
		for _, b := range res.got {
			if b != 0x5a {
				t.Fatal("payload mismatch")
			}
		}
	case <-ctx.Done():
		t.Fatal("credit window stalled")
	}
}

func TestCarrierCloseFailsEveryFlow(t *testing.T) {
	client, _, server, serverIn := startPair(t)
	outgoing, err := client.OpenStream(9)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := serverIn.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	server.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := outgoing.Write([]byte("closed")); err != nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("write kept succeeding after peer close")
}

func TestRapidStreamDropDoesNotCloseCarrier(t *testing.T) {
	client, _, server, serverIn := startPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for flowID := uint32(1); flowID <= 200; flowID++ {
		outgoing, err := client.OpenStream(flowID)
		if err != nil {
			t.Fatalf("open %d: %v", flowID, err)
		}
		accepted, err := serverIn.Accept(ctx)
		if err != nil {
			t.Fatalf("accept %d: %v", flowID, err)
		}
		_ = outgoing.Close()
		_ = accepted.Close()
	}
	if client.IsClosed() || server.IsClosed() {
		t.Fatal("carrier closed after rapid open/drop")
	}
}

func TestAcceptReturnsAfterHandleClose(t *testing.T) {
	client, clientIn, _, _ := startPair(t)
	done := make(chan error, 1)
	go func() {
		_, err := clientIn.Accept(context.Background())
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	client.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Accept returned nil after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return after handle close")
	}
}

func TestCloseInterruptsBlockedRead(t *testing.T) {
	client, _, _, serverIn := startPair(t)
	outgoing, err := client.OpenStream(3)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	incoming, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := incoming.Read(make([]byte, 8))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := incoming.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked Read returned nil after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not interrupt blocked Read")
	}
	_ = outgoing.Close()
}

func TestSetReadDeadlineInterruptsBlockedRead(t *testing.T) {
	client, _, _, serverIn := startPair(t)
	outgoing, err := client.OpenStream(4)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	incoming, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := incoming.Read(make([]byte, 8))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := incoming.SetReadDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !isTimeout(err) {
			t.Fatalf("Read error = %v, want timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SetReadDeadline did not interrupt blocked Read")
	}
	_ = outgoing.Close()
	_ = incoming.Close()
}

func TestDataAfterLocalCloseDoesNotTearDownCarrier(t *testing.T) {
	client, _, server, serverIn := startPair(t)
	first, err := client.OpenStream(5)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	accepted, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write(bytes.Repeat([]byte("x"), 1024)); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	_ = accepted.Close()

	second, err := client.OpenStream(6)
	if err != nil {
		t.Fatal(err)
	}
	other, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(other, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "ok" {
		t.Fatalf("second stream = %q", got)
	}
	if client.IsClosed() || server.IsClosed() {
		t.Fatal("carrier closed after DATA on a locally closed stream")
	}
	_ = second.Close()
	_ = other.Close()
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
