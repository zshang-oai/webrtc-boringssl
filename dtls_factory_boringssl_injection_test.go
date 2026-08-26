// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build boringssl && cgo && !js

package webrtc_test

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/transport/v4/packetio"
	webrtc "github.com/pion/webrtc/v4"
	"github.com/stretchr/testify/require"
)

const injectionTestTimeout = 5 * time.Second

// This is scheduling stress through public APIs, not a forced interleaving
// inside the native connection. An actual peer handshake datagram is injected
// repeatedly while an application Read is active. No test connection deadline
// or private wake method is used, and success requires two-way application data.
func TestBoringSSLFactory_DuplicateRecordInjectionStress(t *testing.T) {
	for _, yield := range []bool{false, true} {
		name := "NoYield"
		if yield {
			name = "YieldBetweenCalls"
		}
		t.Run(name, func(t *testing.T) {
			pair := newInjectionTestPair(t)
			pair.transfer(t, pair.client, pair.server, "warmup-client")
			pair.transfer(t, pair.server, pair.client, "warmup-server")

			packet := pair.clientWire.capturedHandshake()
			require.GreaterOrEqual(t, len(packet), 13, "capture a real DTLS 1.2 handshake datagram")
			injector, ok := pair.server.(interface {
				InjectInboundPacket([]byte, net.Addr) error
			})
			require.True(t, ok, "native factory must expose packet injection")

			const payload = "after-duplicate-record-injection"
			readStarted := pair.serverWire.signalNextRead()
			readDone := pair.start(func() error {
				return readInjectionTestPayload(pair.server, payload)
			})
			waitInjectionTestResult(t, "application Read reaching the transport", readStarted)

			const attempts = 10000
			injectDone := pair.start(func() error {
				for i := 0; i < attempts; i++ {
					select {
					case <-pair.stop:
						return nil
					default:
					}
					if err := injector.InjectInboundPacket(packet, pair.clientWire.LocalAddr()); err != nil {
						return fmt.Errorf("InjectInboundPacket iteration %d: %w", i, err)
					}
					if yield {
						// Yield only between completed public API calls.
						runtime.Gosched()
					}
				}

				return nil
			})
			select {
			case err := <-injectDone:
				require.NoError(t, err)
			case err := <-readDone:
				t.Fatalf("application Read returned before application send: %v", err)
			case <-time.After(injectionTestTimeout):
				t.Fatal("duplicate-record injector blocked")
			}
			select {
			case err := <-readDone:
				t.Fatalf("application Read returned before application send: %v", err)
			default:
			}

			waitInjectionTestResult(t, "client application write", pair.start(func() error {
				return writeInjectionTestPayload(pair.client, payload)
			}))
			waitInjectionTestResult(t, "native application read after injection", readDone)
			pair.transfer(t, pair.server, pair.client, "reply-after-injection")
		})
	}
}

// packetio.Buffer is also used by mux.Endpoint. These endpoints preserve packet
// boundaries and its real deadline behavior without an OS socket. Only the DTLS
// libraries set deadlines; the test's watchdogs only observe progress.
type injectionTestPacketConn struct {
	local, remote net.Addr
	input         *packetio.Buffer
	peer          *injectionTestPacketConn
	mu            sync.Mutex
	lastHandshake []byte
	readStarted   chan error
}

var _ net.PacketConn = (*injectionTestPacketConn)(nil)

func newInjectionTestPacketPair() (*injectionTestPacketConn, *injectionTestPacketConn) {
	client := &injectionTestPacketConn{
		local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 10001}, input: packetio.NewBuffer(),
	}
	server := &injectionTestPacketConn{
		local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 10002}, input: packetio.NewBuffer(),
	}
	client.peer, server.peer = server, client
	client.remote, server.remote = server.local, client.local

	return client, server
}

func (c *injectionTestPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	if c.readStarted != nil {
		// A notification, not a barrier: the read continues immediately.
		c.readStarted <- nil
		c.readStarted = nil
	}
	c.mu.Unlock()
	n, err := c.input.Read(p)

	return n, c.remote, err
}

func (c *injectionTestPacketConn) WriteTo(p []byte, remote net.Addr) (int, error) {
	if remote == nil || remote.Network() != c.remote.Network() || remote.String() != c.remote.String() {
		return 0, fmt.Errorf("unexpected remote: %v", remote)
	}
	// DTLS 1.2 ChangeCipherSpec (20) or Handshake (22), including records
	// coalesced in the same datagram. Capture bytes produced by the real peer.
	if len(p) >= 13 && (p[0] == 20 || p[0] == 22) {
		c.mu.Lock()
		c.lastHandshake = bytes.Clone(p)
		c.mu.Unlock()
	}

	return c.peer.input.Write(p)
}

func (c *injectionTestPacketConn) Close() error        { return c.input.Close() }
func (c *injectionTestPacketConn) LocalAddr() net.Addr { return c.local }
func (c *injectionTestPacketConn) SetReadDeadline(v time.Time) error {
	return c.input.SetReadDeadline(v)
}
func (c *injectionTestPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (c *injectionTestPacketConn) SetDeadline(v time.Time) error    { return c.SetReadDeadline(v) }

func (c *injectionTestPacketConn) capturedHandshake() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	return bytes.Clone(c.lastHandshake)
}

func (c *injectionTestPacketConn) signalNextRead() <-chan error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readStarted = make(chan error, 1)

	return c.readStarted
}

type injectionTestPair struct {
	server                 webrtc.DTLSConn
	client                 *dtls.Conn
	clientWire, serverWire *injectionTestPacketConn
	stop                   chan struct{}
	workers                sync.WaitGroup
}

func newInjectionTestPair(t *testing.T) *injectionTestPair {
	t.Helper()
	pair := &injectionTestPair{stop: make(chan struct{})}
	pair.clientWire, pair.serverWire = newInjectionTestPacketPair()
	t.Cleanup(func() {
		close(pair.stop)
		// Release reads before DTLS Close takes its own locks. Cleanup runs
		// only after the test has observed a result or watchdog failure.
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
		waitInjectionTestResult(t, "connection cleanup and worker exit", done)
	})
	var err error
	pair.server, err = webrtc.NewBoringSSLFactory().Server(
		pair.serverWire, pair.clientWire.LocalAddr(), newInjectionTestConfig(t),
	)
	require.NoError(t, err)
	pair.client, err = dtls.Client(pair.clientWire, pair.serverWire.LocalAddr(), newInjectionTestConfig(t))
	require.NoError(t, err)

	// Pion negotiates DTLS 1.2. The native factory keeps its production
	// version range; neither side receives a test deadline or timed context.
	serverDone := pair.start(pair.server.Handshake)
	clientDone := pair.start(pair.client.Handshake)
	waitInjectionTestResult(t, "Pion client handshake", clientDone)
	waitInjectionTestResult(t, "native server handshake", serverDone)
	_, ok := pair.server.KeyingMaterialExporter()
	require.True(t, ok, "native handshake completed")

	return pair
}

func newInjectionTestConfig(t *testing.T) *dtls.Config {
	t.Helper()
	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	return &dtls.Config{
		Certificates: []tls.Certificate{certificate},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{
			dtls.SRTP_AEAD_AES_128_GCM, dtls.SRTP_AES128_CM_HMAC_SHA1_80,
		},
		ClientAuth:              dtls.RequireAnyClientCert,
		InsecureSkipVerify:      true,
		InsecureSkipVerifyHello: true,
	}
}

func (p *injectionTestPair) start(fn func() error) <-chan error {
	done := make(chan error, 1)
	p.workers.Add(1)
	go func() {
		defer p.workers.Done()
		done <- fn()
	}()

	return done
}

func (p *injectionTestPair) transfer(t *testing.T, sender io.Writer, receiver io.Reader, payload string) {
	t.Helper()
	waitInjectionTestResult(t, "application write", p.start(func() error {
		return writeInjectionTestPayload(sender, payload)
	}))
	waitInjectionTestResult(t, "application read", p.start(func() error {
		return readInjectionTestPayload(receiver, payload)
	}))
}

func writeInjectionTestPayload(sender io.Writer, payload string) error {
	if n, err := sender.Write([]byte(payload)); err != nil {
		return fmt.Errorf("write %q: %w", payload, err)
	} else if n != len(payload) {
		return fmt.Errorf("write %q: got %d bytes", payload, n)
	}

	return nil
}

func readInjectionTestPayload(receiver io.Reader, payload string) error {
	buffer := make([]byte, 2048)
	n, err := receiver.Read(buffer)
	if err != nil {
		return fmt.Errorf("read %q: %w", payload, err)
	}
	if string(buffer[:n]) != payload {
		return fmt.Errorf("read %q: got %q", payload, buffer[:n])
	}

	return nil
}

func waitInjectionTestResult(t *testing.T, name string, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		require.NoError(t, err, name)
	case <-time.After(injectionTestTimeout):
		t.Fatalf("timed out waiting for %s", name)
	}
}
