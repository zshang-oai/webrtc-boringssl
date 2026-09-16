// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build boringssl && cgo && !js

package webrtc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func TestBoringSSLFlight_PublishOnlyAtFlush(t *testing.T) {
	wire := newFlightTestWire()
	conn := &boringSSLConn{Conn: wire}
	var flights [][][]byte
	conn.SetOutboundHandshakePacketInterceptor(func(flight [][]byte, _ net.Addr) bool {
		flights = append(flights, flight)
		return true
	})
	packet := []byte("first datagram")
	_, err := conn.queueOrWritePacketLocked(packet)
	require.NoError(t, err)
	packet[0] = 'X' // The producer may reuse its buffer before the BIO flush.
	_, err = conn.queueOrWritePacketLocked([]byte("second datagram"))
	require.NoError(t, err)
	require.Empty(t, flights)
	require.Empty(t, wire.writes)
	require.NoError(t, conn.flushPacketsLocked())
	want := [][]byte{[]byte("first datagram"), []byte("second datagram")}
	require.Equal(t, [][][]byte{want}, flights)
	require.Empty(t, wire.writes, "consumption applies to the whole flight")

	// A retransmitted flight is another complete submission, not cumulative
	// output left over from the prior flush. An empty flush submits nothing.
	for _, packet := range want {
		_, err = conn.queueOrWritePacketLocked(packet)
		require.NoError(t, err)
	}
	require.NoError(t, conn.flushPacketsLocked())
	require.NoError(t, conn.flushPacketsLocked())
	require.Equal(t, [][][]byte{want, want}, flights)

	conn.finishHandshake(nil)
	_, err = conn.queueOrWritePacketLocked([]byte("application data"))
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("application data")}, wire.writes,
		"application output must not wait for a handshake flush")
	require.Len(t, flights, 2)
}

func TestBoringSSLFlight_PlainFallback(t *testing.T) {
	for _, detach := range []bool{false, true} {
		name := "Declined"
		if detach {
			name = "DetachedBeforeFlush"
		}
		t.Run(name, func(t *testing.T) {
			wire := newFlightTestWire()
			conn := &boringSSLConn{Conn: wire}
			calls := 0
			conn.SetOutboundHandshakePacketInterceptor(func(flight [][]byte, _ net.Addr) bool {
				calls++
				require.Len(t, flight, 3)
				return false
			})
			want := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
			for _, packet := range want {
				_, err := conn.queueOrWritePacketLocked(packet)
				require.NoError(t, err)
			}
			if detach {
				conn.SetOutboundHandshakePacketInterceptor(nil)
			}
			require.Empty(t, wire.writes)
			require.NoError(t, conn.flushPacketsLocked())
			require.Equal(t, want, wire.writes)
			if detach {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
			}
		})
	}
}

func TestBoringSSLFlight_FallbackFailureClearsBatch(t *testing.T) {
	writeErr := errors.New("flight transport failed")
	for _, tc := range []struct {
		name string
		want error
	}{
		{"WriteError", writeErr},
		{"ShortWrite", io.ErrShortWrite},
		{"DeadlineBetweenDatagrams", os.ErrDeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := newFlightTestWire()
			conn := &boringSSLConn{Conn: wire}
			conn.SetOutboundHandshakePacketInterceptor(func([][]byte, net.Addr) bool { return false })
			wire.write = func(packet []byte) (int, error) {
				if tc.want == os.ErrDeadlineExceeded {
					require.NoError(t, conn.SetWriteDeadline(time.Now()))
				} else if len(wire.writes) == 2 {
					if tc.want == io.ErrShortWrite {
						return len(packet) - 1, nil
					}
					return 0, tc.want
				}
				return len(packet), nil
			}
			for _, packet := range [][]byte{[]byte("one"), []byte("two"), []byte("three")} {
				_, err := conn.queueOrWritePacketLocked(packet)
				require.NoError(t, err)
			}
			require.ErrorIs(t, conn.flushPacketsLocked(), tc.want)
			require.Nil(t, conn.pendingHandshakeFlight)
			written := len(wire.writes)
			require.Less(t, written, 3, "do not write later datagrams after an error")
			require.NoError(t, conn.flushPacketsLocked())
			require.Len(t, wire.writes, written, "a failed batch is not replayed by another flush")
		})
	}
}

// Exercise BoringSSL's actual BIO_flush -> WANT_WRITE path. A hard fallback or
// underlying Flush error must reach HandshakeContext, not be cleared on retry.
func TestBoringSSLFactory_FlightFlushError(t *testing.T) {
	writeErr := errors.New("native flight write failed")
	flushErr := errors.New("native wire flush failed")
	for _, tc := range []struct {
		name string
		want error
	}{
		{"Write", writeErr},
		{"ShortWrite", io.ErrShortWrite},
		{"Flush", flushErr},
		{"Deadline", os.ErrDeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := newFlightTestWire()
			conn, err := newBoringSSLConn(wire, newInteropDTLSConfig(t), true)
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			wire.write = func(packet []byte) (int, error) {
				switch tc.want {
				case writeErr:
					return 0, writeErr
				case io.ErrShortWrite:
					return len(packet) - 1, nil
				}
				return len(packet), nil
			}
			if tc.want == flushErr {
				wire.flushErr = flushErr
			}
			conn.SetOutboundHandshakePacketInterceptor(func([][]byte, net.Addr) bool {
				if tc.want == os.ErrDeadlineExceeded {
					_ = conn.SetWriteDeadline(time.Now())
				}
				return false
			})
			done := make(chan error, 1)
			go func() { done <- conn.HandshakeContext(context.Background()) }()
			require.ErrorIs(t, awaitReadRecordTest(t, done), tc.want)
			require.Nil(t, conn.pendingHandshakeFlight)
			require.ErrorIs(t, conn.InjectInboundPacket([]byte("late input"), nil), tc.want,
				"failure must also terminate later injected waiters")
		})
	}
}

func TestBoringSSLFactory_InjectedInputWaitsForFlightPublication(t *testing.T) {
	clientWire, serverWire := newLocalUDPConn(t), newLocalUDPConn(t)
	client, err := NewBoringSSLFactory().Client(packetConnOnly{clientWire}, serverWire.LocalAddr(), newInteropDTLSConfig(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	serverConfig := newInteropDTLSConfig(t)
	serverConfig.InsecureSkipVerifyHello = true
	serverConfig.MTU = 256
	server, err := NewBoringSSLFactory().Server(packetConnOnly{serverWire}, clientWire.LocalAddr(), serverConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	clientFlight := make(chan [][]byte, 1)
	client.(*boringSSLConn).SetOutboundHandshakePacketInterceptor(func(flight [][]byte, _ net.Addr) bool {
		select {
		case clientFlight <- flight:
		default:
		}
		return true
	})
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.HandshakeContext(ctx) }()
	flight := awaitReadRecordTest(t, clientFlight)
	require.Len(t, flight, 1, "use one actual ClientHello as the embedded input")

	publicationStarted := make(chan int, 1)
	releasePublication := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(releasePublication) }) }
	t.Cleanup(release)
	native := server.(*boringSSLConn)
	native.SetOutboundHandshakePacketInterceptor(func(flight [][]byte, _ net.Addr) bool {
		publicationStarted <- len(flight)
		<-releasePublication
		return true
	})
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.HandshakeContext(ctx) }()
	injectedDone := make(chan error, 1)
	go func() { injectedDone <- native.InjectInboundPacket(flight[0], clientWire.LocalAddr()) }()
	require.Greater(t, awaitReadRecordTest(t, publicationStarted), 1,
		"publish the fragmented response as one complete flight")
	select {
	case err := <-injectedDone:
		t.Fatalf("embedded input completed before response-flight publication: %v", err)
	default:
	}
	release()
	require.NoError(t, awaitReadRecordTest(t, injectedDone))
	cancel()
	require.ErrorIs(t, awaitReadRecordTest(t, serverDone), context.Canceled)
	require.ErrorIs(t, awaitReadRecordTest(t, clientDone), context.Canceled)
}

// A deliberately small native MTU forces actual fragmented certificate flights.
// Both DTLS versions must still interoperate when ICE declines the complete
// flight, and application records must bypass the interceptor after completion.
func TestBoringSSLFactory_FragmentedFlightFallback(t *testing.T) {
	for _, nativePeer := range []bool{false, true} {
		name := "DTLS12PionPeer"
		wantVersion := protocol.Version1_2
		if nativePeer {
			name = "DTLS13NativePeer"
			wantVersion = protocol.Version1_3
		}
		t.Run(name, func(t *testing.T) {
			clientWire, serverWire := newLocalUDPConn(t), newLocalUDPConn(t)
			cfg := newInteropDTLSConfig(t)
			cfg.InsecureSkipVerifyHello = true
			cfg.MTU = 256
			server, err := NewBoringSSLFactory().Server(packetConnOnly{serverWire}, clientWire.LocalAddr(), cfg)
			require.NoError(t, err)
			t.Cleanup(func() { _ = server.Close() })
			var client DTLSConn
			if nativePeer {
				client, err = NewBoringSSLFactory().Client(packetConnOnly{clientWire}, serverWire.LocalAddr(), newInteropDTLSConfig(t))
			} else {
				var pion *dtls.Conn
				pion, err = dtls.Client(clientWire, serverWire.LocalAddr(), newInteropDTLSConfig(t))
				client = &pionDTLSConn{Conn: pion}
			}
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })
			native := server.(*boringSSLConn)
			var mu sync.Mutex
			var sizes []int
			native.SetOutboundHandshakePacketInterceptor(func(flight [][]byte, _ net.Addr) bool {
				mu.Lock()
				sizes = append(sizes, len(flight))
				mu.Unlock()
				return false
			})
			serverDone := make(chan error, 1)
			go func() { serverDone <- runInteropServer(server) }()
			require.Equal(t, "pong", runInteropClient(t, client))
			require.NoError(t, awaitReadRecordTest(t, serverDone))
			require.Equal(t, wantVersion, native.DTLSVersion())
			mu.Lock()
			defer mu.Unlock()
			require.NotEmpty(t, sizes)
			require.Greater(t, sizes[0], 1, "first server flight must contain multiple actual BIO writes")
			t.Logf("native flight datagram counts: %v", sizes)
		})
	}
}

type flightTestWire struct {
	*readRecordTestWire
	writes   [][]byte
	write    func([]byte) (int, error)
	flushErr error
}

func newFlightTestWire() *flightTestWire {
	return &flightTestWire{readRecordTestWire: &readRecordTestWire{
		reads: make(chan chan readRecordTestResult, 8), closed: make(chan struct{}),
	}}
}

func (c *flightTestWire) Write(packet []byte) (int, error) {
	c.writes = append(c.writes, bytes.Clone(packet))
	if c.write != nil {
		return c.write(packet)
	}
	return len(packet), nil
}

func (c *flightTestWire) Flush() error { return c.flushErr }
