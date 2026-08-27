// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build boringssl && cgo && !js

package webrtc_test

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	webrtc "github.com/pion/webrtc/v4"
	"github.com/stretchr/testify/require"
)

// These are real concurrent application Writes while the native reader is
// idle. They do not claim to force SSL_write to return SSL_ERROR_WANT_READ.
func TestBoringSSLFactory_ConcurrentWritesWithIdleRead(t *testing.T) {
	pair := newInjectionTestPair(t)
	const reply = "release-idle-native-reader"
	readStarted := pair.serverWire.signalNextRead()
	readDone := pair.start(func() error { return readInjectionTestPayload(pair.server, reply) })
	waitInjectionTestResult(t, "idle native Read reaching the transport", readStarted)

	const count = 16
	payloads := make([]string, count)
	expected := make(map[string]bool, count)
	for i := range payloads {
		payloads[i] = fmt.Sprintf("native-writer-%02d:%s", i, strings.Repeat("distinct", i+1))
		expected[payloads[i]] = true
	}
	received := pair.start(func() error {
		buffer := make([]byte, 2048)
		for range count {
			n, err := pair.client.Read(buffer)
			if err != nil {
				return err
			}
			payload := string(buffer[:n])
			if !expected[payload] {
				return fmt.Errorf("unexpected or duplicate concurrent payload: %q", payload)
			}
			delete(expected, payload)
		}

		return nil
	})
	start := make(chan struct{})
	writers := make([]<-chan error, count)
	for i, payload := range payloads {
		writers[i] = pair.start(func() error {
			<-start

			return writeInjectionTestPayload(pair.server, payload)
		})
	}
	close(start)
	for _, done := range writers {
		waitInjectionTestResult(t, "concurrent native application Write", done)
	}
	waitInjectionTestResult(t, "all distinct concurrent payloads", received)
	select {
	case err := <-readDone:
		t.Fatalf("idle native Read returned before its application payload: %v", err)
	default:
	}
	waitInjectionTestResult(t, "reply to idle native reader", pair.start(func() error {
		return writeInjectionTestPayload(pair.client, reply)
	}))
	waitInjectionTestResult(t, "native Read after concurrent Writes", readDone)
}

// Drop the native server's entire first flight, then require a matching
// ServerHello retransmission before any second ClientHello. The Pion client's
// retransmission interval is longer than the test watchdog, so it cannot rescue
// the handshake. This tests the real native retransmission timer, without an
// injected record, private C adapter, or test-supplied connection deadline.
func TestBoringSSLFactory_RetransmitsLostFirstFlight(t *testing.T) {
	pair := &injectionTestPair{stop: make(chan struct{})}
	pair.clientWire, pair.serverWire = newInjectionTestPacketPair()
	t.Cleanup(func() {
		close(pair.stop)
		_ = pair.clientWire.Close()
		_ = pair.serverWire.Close()
		done := make(chan error, 1)
		go func() {
			if pair.client != nil {
				_ = pair.client.Close()
			}
			if pair.server != nil {
				_ = pair.server.Close()
			}
			pair.workers.Wait()
			done <- nil
		}()
		waitInjectionTestResult(t, "loss-test cleanup and worker exit", done)
	})
	clientWire := &progressClientHelloConn{PacketConn: pair.clientWire}
	serverWire := &progressFirstFlightLossConn{PacketConn: pair.serverWire, client: clientWire}
	var err error
	pair.server, err = webrtc.NewBoringSSLFactory().Server(
		serverWire, pair.clientWire.LocalAddr(), newInjectionTestConfig(t),
	)
	require.NoError(t, err)
	clientConfig := newInjectionTestConfig(t)
	// Pion config.FlightInterval becomes the handshake FSM's initial
	// retransmit interval. Do not set this unsupported option on the native side.
	clientConfig.FlightInterval = time.Minute
	pair.client, err = dtls.Client(clientWire, pair.serverWire.LocalAddr(), clientConfig)
	require.NoError(t, err)
	serverDone := pair.start(pair.server.Handshake)
	clientDone := pair.start(pair.client.Handshake)
	waitInjectionTestResult(t, "client handshake after native flight loss", clientDone)
	waitInjectionTestResult(t, "native handshake after first-flight retransmission", serverDone)

	serverWire.mu.Lock()
	dropped, retransmits := serverWire.dropped, serverWire.retransmits
	clientHellos, elapsed := serverWire.clientHellosAtRetransmit, serverWire.firstRetransmitAfter
	serverWire.mu.Unlock()
	require.Positive(t, dropped, "the native first flight must actually be dropped")
	require.Positive(t, retransmits, "observe the same native ServerHello handshake fragment again")
	require.Equal(t, uint32(1), clientHellos, "the native retransmission must precede any client retry")
	require.Less(t, elapsed, clientConfig.FlightInterval)
	t.Logf("dropped %d native datagrams; matching ServerHello retransmits=%d; first after %s; client hellos=%d",
		dropped, retransmits, elapsed, clientHellos)
	pair.transfer(t, pair.client, pair.server, "client-after-flight-loss")
	pair.transfer(t, pair.server, pair.client, "native-after-retransmission")
}

type progressClientHelloConn struct {
	net.PacketConn
	hellos atomic.Uint32
}

func (c *progressClientHelloConn) WriteTo(packet []byte, addr net.Addr) (int, error) {
	if progressHandshakeFragment(packet, handshake.TypeClientHello) != nil {
		c.hellos.Add(1)
	}

	return c.PacketConn.WriteTo(packet, addr)
}

type progressFirstFlightLossConn struct {
	net.PacketConn
	client                   *progressClientHelloConn
	mu                       sync.Mutex
	firstFlightEnded         bool
	dropped                  int
	firstServerHello         []byte
	firstFlightAt            time.Time
	retransmits              int
	clientHellosAtRetransmit uint32
	firstRetransmitAfter     time.Duration
}

func (c *progressFirstFlightLossConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	c.mu.Lock()
	if c.dropped > 0 {
		// A raw input wait after output marks the flight boundary. The initial
		// read of ClientHello (before any output) does not end the drop phase.
		c.firstFlightEnded = true
	}
	c.mu.Unlock()

	return c.PacketConn.ReadFrom(packet)
}

func (c *progressFirstFlightLossConn) WriteTo(packet []byte, addr net.Addr) (int, error) {
	hello := progressHandshakeFragment(packet, handshake.TypeServerHello)
	c.mu.Lock()
	if !c.firstFlightEnded {
		if c.dropped == 0 {
			c.firstFlightAt = time.Now()
		}
		c.dropped++
		if hello != nil && c.firstServerHello == nil {
			c.firstServerHello = bytes.Clone(hello)
		}
		c.mu.Unlock()

		return len(packet), nil // Deliberate packet loss, not a write failure.
	}
	if hello != nil && bytes.Equal(hello, c.firstServerHello) {
		c.retransmits++
		if c.retransmits == 1 {
			c.clientHellosAtRetransmit = c.client.hellos.Load()
			c.firstRetransmitAfter = time.Since(c.firstFlightAt)
		}
	}
	c.mu.Unlock()

	return c.PacketConn.WriteTo(packet, addr)
}

// Match a plaintext handshake fragment, excluding the DTLS record header whose
// sequence number changes on retransmission. Parse coalesced records/messages;
// encrypted epoch-one records and unrelated handshake messages are ignored.
func progressHandshakeFragment(datagram []byte, kind handshake.Type) []byte {
	records, err := recordlayer.UnpackDatagram(datagram)
	if err != nil {
		return nil
	}
	for _, record := range records {
		var header recordlayer.Header
		if header.Unmarshal(record) != nil || header.ContentType != protocol.ContentTypeHandshake || header.Epoch != 0 {
			continue
		}
		payload := record[header.Size():]
		for len(payload) >= handshake.HeaderLength {
			var fragment handshake.Header
			if fragment.Unmarshal(payload) != nil {
				break
			}
			size := handshake.HeaderLength + int(fragment.FragmentLength)
			if size > len(payload) {
				break
			}
			if fragment.Type == kind && fragment.FragmentOffset == 0 {
				return payload[:size]
			}
			payload = payload[size:]
		}
	}

	return nil
}
