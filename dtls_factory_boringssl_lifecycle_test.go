// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build boringssl && cgo && !js

package webrtc_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	webrtc "github.com/pion/webrtc/v4"
	"github.com/stretchr/testify/require"
)

// Unlike the no-deadline injection regression, this deliberately requests a
// real application timeout. Injection must not hide it or prevent later reuse.
func TestBoringSSLFactory_InjectionPreservesReadDeadline(t *testing.T) {
	pair := newInjectionTestPair(t)
	pair.transfer(t, pair.client, pair.server, "before-deadline")
	deadline := time.Now().Add(50 * time.Millisecond)
	readStarted := pair.serverWire.signalNextRead()
	readDone := pair.start(func() error {
		_, err := pair.server.Read(make([]byte, 64))
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			return fmt.Errorf("application Read: expected deadline exceeded, got %v", err)
		}
		if time.Now().Before(deadline) {
			return errors.New("application Read timed out before its requested deadline")
		}

		return nil
	})
	waitInjectionTestResult(t, "application Read reaching the transport", readStarted)
	stop, injectDone := startLifecycleInjections(t, pair, nil)
	// Exercise a deadline update while the read and injector are already active.
	require.NoError(t, pair.server.SetReadDeadline(deadline))
	waitInjectionTestResult(t, "requested application read timeout", readDone)
	stop()
	waitInjectionTestResult(t, "deadline-test injector exit", injectDone)

	require.NoError(t, pair.server.SetReadDeadline(time.Time{}))
	pair.transfer(t, pair.client, pair.server, "after-cleared-deadline")
	pair.transfer(t, pair.server, pair.client, "reply-after-cleared-deadline")
}

func TestBoringSSLFactory_SilentHandshakeContext(t *testing.T) {
	for _, tc := range []struct {
		name string
		want error
	}{
		{"Cancel", context.Canceled},
		{"DeadlineExceeded", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pair := newSilentLifecycleServer(t)
			// Start the context clock after certificate and native factory setup.
			var ctx context.Context
			var cancel context.CancelFunc
			if tc.want == context.Canceled {
				ctx, cancel = context.WithCancel(context.Background())
			} else {
				ctx, cancel = context.WithTimeout(context.Background(), 250*time.Millisecond)
			}
			t.Cleanup(cancel)
			readStarted := pair.serverWire.signalNextRead()
			handshakeDone := pair.start(func() error {
				if err := pair.server.HandshakeContext(ctx); !errors.Is(err, tc.want) {
					return fmt.Errorf("silent handshake: expected %v, got %v", tc.want, err)
				}

				return nil
			})
			waitInjectionTestResult(t, "silent handshake reaching the transport", readStarted)
			if tc.want == context.Canceled {
				cancel()
			}
			waitInjectionTestResult(t, "handshake context termination", handshakeDone)
		})
	}
}

func TestBoringSSLFactory_CloseDuringReadAndInjection(t *testing.T) {
	pair := newInjectionTestPair(t)
	pair.transfer(t, pair.client, pair.server, "before-close")
	closing := make(chan struct{})
	readStarted := pair.serverWire.signalNextRead()
	readDone := pair.start(func() error {
		_, err := pair.server.Read(make([]byte, 64))
		if err == nil {
			return errors.New("application Read unexpectedly succeeded without a payload")
		}
		select {
		case <-closing:
			// Close may win through the closed transport or its read deadline.
			return nil
		default:
			return fmt.Errorf("application Read returned before Close: %w", err)
		}
	})
	waitInjectionTestResult(t, "application Read reaching the transport", readStarted)
	stop, injectDone := startLifecycleInjections(t, pair, closing)
	closeDone := pair.start(func() error {
		close(closing)
		defer stop()

		return pair.server.Close()
	})
	waitInjectionTestResult(t, "native Close", closeDone)
	waitInjectionTestResult(t, "application Read released by Close", readDone)
	waitInjectionTestResult(t, "close-test injector exit", injectDone)
}

// Keep real duplicate input arriving until the lifecycle operation ends. This
// is paced input, not another large scheduling-stress loop. The context stops
// only this test worker; it is never passed to the native connection.
func startLifecycleInjections(
	t *testing.T, pair *injectionTestPair, closing <-chan struct{},
) (context.CancelFunc, <-chan error) {
	t.Helper()
	packet := pair.clientWire.capturedHandshake()
	require.GreaterOrEqual(t, len(packet), 13, "capture a real peer handshake datagram")
	injector, ok := pair.server.(interface {
		InjectInboundPacket([]byte, net.Addr) error
	})
	require.True(t, ok)
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	started := make(chan error, 1)
	done := pair.start(func() error {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for first := true; ; first = false {
			err := injector.InjectInboundPacket(packet, pair.clientWire.LocalAddr())
			if first {
				started <- err
			}
			if err != nil {
				select {
				case <-closing:
					return nil
				default:
					return fmt.Errorf("duplicate-record injection: %w", err)
				}
			}
			select {
			case <-ctx.Done():
				return nil
			case <-pair.stop:
				return nil
			case <-ticker.C:
			}
		}
	})
	waitInjectionTestResult(t, "first duplicate-record injection", started)

	return stop, done
}

// Reuse the memory transport and worker tracking without starting a peer DTLS
// client. The native server can exit its first input wait only via its context
// or cleanup, not a successful handshake or application traffic.
func newSilentLifecycleServer(t *testing.T) *injectionTestPair {
	t.Helper()
	pair := &injectionTestPair{stop: make(chan struct{})}
	pair.clientWire, pair.serverWire = newInjectionTestPacketPair()
	t.Cleanup(func() {
		close(pair.stop)
		_ = pair.clientWire.Close()
		_ = pair.serverWire.Close()
		done := make(chan error, 1)
		go func() {
			if pair.server != nil {
				_ = pair.server.Close()
			}
			pair.workers.Wait()
			done <- nil
		}()
		waitInjectionTestResult(t, "silent server cleanup and worker exit", done)
	})
	var err error
	pair.server, err = webrtc.NewBoringSSLFactory().Server(
		pair.serverWire, pair.clientWire.LocalAddr(), newInjectionTestConfig(t),
	)
	require.NoError(t, err)

	return pair
}
