// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build boringssl && cgo && !js

package webrtc

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBoringSSLReadRecord_QueuedInjectionDoesNotArmRead(t *testing.T) {
	conn, wire := newReadRecordTestConn(t)
	require.NoError(t, conn.enqueueInjectedPacket([]byte("queued record"), nil))
	require.NoError(t, awaitReadRecordTest(t, conn.startRead(context.Background(), readDeadlineUserRead)))
	require.Nil(t, conn.readWait)
	require.True(t, wire.readDeadline().IsZero())
	select {
	case <-wire.reads:
		t.Fatal("queued input must be consumed before registering a transport read")
	default:
	}
}

func TestBoringSSLReadRecord_InternalWakeIsGenerationScoped(t *testing.T) {
	conn, wire := newReadRecordTestConn(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstDone := conn.startRead(ctx, readDeadlineUserRead)
	firstRead := awaitReadRecordTest(t, wire.reads)
	conn.deadlineMu.Lock()
	firstWait := conn.readWait
	conn.deadlineMu.Unlock()
	require.NotNil(t, firstWait)

	require.NoError(t, conn.enqueueInjectedPacket([]byte("injected record"), nil))
	require.True(t, deadlineExceeded(wire.readDeadline()), "injection interrupts the registered read")
	// Terminal handshake cleanup can consume queued input before the raw read
	// reports its interrupt. The interrupt still belongs to this read only.
	conn.finishHandshake(nil)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Hour)))
	require.True(t, deadlineExceeded(wire.readDeadline()), "a future user deadline must not erase the wake")
	require.NoError(t, conn.SetReadDeadline(time.Time{}))
	require.NoError(t, conn.SetWriteDeadline(time.Now().Add(time.Hour)))
	require.True(t, deadlineExceeded(wire.readDeadline()), "clearing or changing another deadline must not erase the wake")
	firstRead <- readRecordTestResult{err: os.ErrDeadlineExceeded}
	require.NoError(t, awaitReadRecordTest(t, firstDone), "an internal wake with an empty queue is not an application timeout")
	awaitReadRecordTest(t, firstWait.done)
	require.True(t, wire.readDeadline().IsZero())

	secondDone := conn.startRead(context.Background(), readDeadlineUserRead)
	secondRead := awaitReadRecordTest(t, wire.reads)
	conn.deadlineMu.Lock()
	secondWait := conn.readWait
	conn.deadlineMu.Unlock()
	require.NotSame(t, firstWait, secondWait)
	// Cancel the completed operation after the next generation has started.
	cancel()
	require.True(t, wire.readDeadline().IsZero(), "old cancellation must not interrupt the next generation")
	unexpectedTimeout := &readRecordTestTimeout{}
	secondRead <- readRecordTestResult{err: unexpectedTimeout}
	require.ErrorIs(t, awaitReadRecordTest(t, secondDone), unexpectedTimeout,
		"an unrelated transport timeout must not inherit the previous internal wake")
}

func TestBoringSSLReadRecord_ContenderWaitsForBIODelivery(t *testing.T) {
	conn, wire := newReadRecordTestConn(t)
	beforeBIO := make(chan struct{})
	releaseBIO := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseBIO) }) }
	t.Cleanup(release)
	conn.SetInboundHandshakePacketNotifier(func([]byte) {
		close(beforeBIO)
		<-releaseBIO
	})

	ownerDone := conn.startRead(context.Background(), readDeadlineUserRead)
	ownerRead := awaitReadRecordTest(t, wire.reads)
	conn.deadlineMu.Lock()
	owner := conn.readWait
	conn.deadlineMu.Unlock()
	contenderDone := conn.startRead(context.Background(), readDeadlineUserWrite)
	conn.awaitContender(t)
	conn.deadlineMu.Lock()
	currentOwner := conn.readWait
	conn.deadlineMu.Unlock()
	require.Same(t, owner, currentOwner, "a contender must not publish another read generation")

	ownerRead <- readRecordTestResult{packet: []byte("network record")}
	awaitReadRecordTest(t, beforeBIO)
	select {
	case <-owner.done:
		t.Fatal("ownership ended before the received input reached the BIO")
	default:
	}
	select {
	case err := <-contenderDone:
		t.Fatalf("contender returned before BIO delivery: %v", err)
	default:
	}
	release()
	require.NoError(t, awaitReadRecordTest(t, ownerDone))
	require.NoError(t, awaitReadRecordTest(t, contenderDone))
	select {
	case <-wire.reads:
		t.Fatal("contender must retry SSL after owner progress, not issue a second raw read")
	default:
	}
}

func TestBoringSSLReadRecord_ContenderDeadlineDoesNotInterruptOwner(t *testing.T) {
	conn, wire := newReadRecordTestConn(t)
	ownerDone := conn.startRead(context.Background(), readDeadlineUserRead)
	ownerRead := awaitReadRecordTest(t, wire.reads)
	contenderDone := conn.startRead(context.Background(), readDeadlineUserWrite)
	conn.awaitContender(t)
	require.NoError(t, conn.SetWriteDeadline(time.Now()))
	require.ErrorIs(t, awaitReadRecordTest(t, contenderDone), os.ErrDeadlineExceeded)
	require.True(t, wire.readDeadline().IsZero(), "a waiting writer must not change the raw reader's deadline")
	select {
	case err := <-ownerDone:
		t.Fatalf("writer deadline interrupted the read owner: %v", err)
	default:
	}
	ownerRead <- readRecordTestResult{err: io.EOF}
	require.ErrorIs(t, awaitReadRecordTest(t, ownerDone), io.EOF)
}

func TestBoringSSLReadRecord_ContenderCancellationDoesNotInterruptOwner(t *testing.T) {
	conn, wire := newReadRecordTestConn(t)
	ownerDone := conn.startRead(context.Background(), readDeadlineUserRead)
	ownerRead := awaitReadRecordTest(t, wire.reads)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	contenderDone := conn.startRead(ctx, readDeadlineNone)
	conn.awaitContender(t)
	cancel()
	require.ErrorIs(t, awaitReadRecordTest(t, contenderDone), context.Canceled)
	require.True(t, wire.readDeadline().IsZero())
	ownerRead <- readRecordTestResult{err: io.EOF}
	require.ErrorIs(t, awaitReadRecordTest(t, ownerDone), io.EOF)
}

func TestBoringSSLReadRecord_ContenderDeadlineCanBeExtendedOrCleared(t *testing.T) {
	for _, clear := range []bool{false, true} {
		name := "Extend"
		if clear {
			name = "Clear"
		}
		t.Run(name, func(t *testing.T) {
			conn, wire := newReadRecordTestConn(t)
			// Initialize before either goroutine starts, so awaitContender can
			// observe the first registration of a deadline-change notification.
			oldDeadline := time.Now().Add(250 * time.Millisecond)
			conn.writeDeadline = oldDeadline
			ownerDone := conn.startRead(context.Background(), readDeadlineUserRead)
			ownerRead := awaitReadRecordTest(t, wire.reads)
			contenderDone := conn.startRead(context.Background(), readDeadlineUserWrite)
			conn.awaitContender(t)
			newDeadline := time.Now().Add(time.Hour)
			if clear {
				newDeadline = time.Time{}
			}
			require.NoError(t, conn.SetWriteDeadline(newDeadline))
			select {
			case err := <-contenderDone:
				t.Fatalf("contender used the replaced deadline: %v", err)
			case <-time.After(time.Until(oldDeadline.Add(25 * time.Millisecond))):
			}
			require.True(t, wire.readDeadline().IsZero())
			require.NoError(t, conn.SetWriteDeadline(time.Now()))
			require.ErrorIs(t, awaitReadRecordTest(t, contenderDone), os.ErrDeadlineExceeded)
			ownerRead <- readRecordTestResult{err: io.EOF}
			require.ErrorIs(t, awaitReadRecordTest(t, ownerDone), io.EOF)
		})
	}
}

func TestBoringSSLReadRecord_RealDeadlineWinsOverInjection(t *testing.T) {
	for _, kind := range []readDeadlineKind{readDeadlineUserRead, readDeadlineUserWrite} {
		name := "Read"
		if kind == readDeadlineUserWrite {
			name = "Write"
		}
		t.Run(name, func(t *testing.T) {
			conn, wire := newReadRecordTestConn(t)
			done := conn.startRead(context.Background(), kind)
			read := awaitReadRecordTest(t, wire.reads)
			require.NoError(t, conn.enqueueInjectedPacket([]byte("injected record"), nil))
			if kind == readDeadlineUserRead {
				require.NoError(t, conn.SetReadDeadline(time.Now()))
			} else {
				require.NoError(t, conn.SetWriteDeadline(time.Now()))
			}
			read <- readRecordTestResult{err: os.ErrDeadlineExceeded}
			require.ErrorIs(t, awaitReadRecordTest(t, done), os.ErrDeadlineExceeded)
			_, queued := conn.takeInjectedPacket()
			require.True(t, queued, "a genuine deadline must not consume injected input to hide the timeout")
		})
	}
}

func TestBoringSSLReadRecord_ContextCancellationWakesOwner(t *testing.T) {
	conn, wire := newReadRecordTestConn(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := conn.startRead(ctx, readDeadlineNone)
	read := awaitReadRecordTest(t, wire.reads)
	cancel()
	require.Eventually(t, func() bool { return deadlineExceeded(wire.readDeadline()) }, time.Second, time.Millisecond)
	read <- readRecordTestResult{err: os.ErrDeadlineExceeded}
	require.ErrorIs(t, awaitReadRecordTest(t, done), context.Canceled)
	require.True(t, wire.readDeadline().IsZero())
}

func TestBoringSSLReadRecord_CloseReleasesOwnerAndContender(t *testing.T) {
	conn, wire := newReadRecordTestConn(t)
	ownerDone := conn.startRead(context.Background(), readDeadlineUserRead)
	awaitReadRecordTest(t, wire.reads)
	contenderDone := conn.startRead(context.Background(), readDeadlineUserWrite)
	conn.awaitContender(t)
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	require.NoError(t, awaitReadRecordTest(t, closed))
	require.ErrorIs(t, awaitReadRecordTest(t, ownerDone), io.ErrClosedPipe)
	// The raw reader can deliver its error before Close acquires the SSL lock;
	// in that order a contender gets a retry, then its next SSL step sees Close.
	err := awaitReadRecordTest(t, contenderDone)
	require.True(t, err == nil || errors.Is(err, io.ErrClosedPipe), "unexpected contender result: %v", err)
}

func TestBoringSSLFactory_ExpiredWriteDeadlineDoesNotWaitForAnotherWrite(t *testing.T) {
	conn, _ := newReadRecordTestConn(t)
	conn.writeOpMu.Lock()
	t.Cleanup(conn.writeOpMu.Unlock)
	require.NoError(t, conn.SetWriteDeadline(time.Now()))
	done := make(chan error, 1)
	conn.workers.Add(1)
	go func() {
		defer conn.workers.Done()
		_, err := conn.Write([]byte("expired write"))
		done <- err
	}()
	require.ErrorIs(t, awaitReadRecordTest(t, done), os.ErrDeadlineExceeded)
}

// These unit tests choose read results and interleavings explicitly. The public
// injection stress in the external test package separately reproduces the bug
// with real DTLS records and real packetio deadline behavior.
type readRecordTestConn struct {
	*boringSSLConn
	workers sync.WaitGroup
}

func newReadRecordTestConn(t *testing.T) (*readRecordTestConn, *readRecordTestWire) {
	t.Helper()
	wire := &readRecordTestWire{reads: make(chan chan readRecordTestResult, 8), closed: make(chan struct{})}
	cfg := newInteropDTLSConfig(t)
	cfg.InsecureSkipVerifyHello = true
	native, err := newBoringSSLConn(wire, cfg, false)
	require.NoError(t, err)
	conn := &readRecordTestConn{boringSSLConn: native}
	t.Cleanup(func() {
		_ = wire.Close()
		_ = conn.Close()
		done := make(chan struct{})
		go func() { conn.workers.Wait(); close(done) }()
		awaitReadRecordTest(t, done)
	})

	return conn, wire
}

func (c *readRecordTestConn) startRead(ctx context.Context, kind readDeadlineKind) <-chan error {
	done := make(chan error, 1)
	c.workers.Add(1)
	go func() {
		defer c.workers.Done()
		c.mu.Lock()
		defer c.mu.Unlock()
		_, err := c.readRecord(ctx, kind)
		done <- err
	}()

	return done
}

func (c *readRecordTestConn) awaitContender(t *testing.T) {
	t.Helper()
	// These fresh connections have no user deadline updates. The first
	// contender creates the change notification while registering its wait.
	require.Eventually(t, func() bool {
		c.deadlineMu.Lock()
		defer c.deadlineMu.Unlock()

		return c.deadlineChanged != nil
	}, time.Second, time.Millisecond)
}

func awaitReadRecordTest[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for native read test progress")
		var zero T

		return zero
	}
}

type readRecordTestResult struct {
	packet []byte
	err    error
}

type readRecordTestWire struct {
	reads     chan chan readRecordTestResult
	closed    chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	deadline  time.Time
}

func (c *readRecordTestWire) Read(p []byte) (int, error) {
	result := make(chan readRecordTestResult, 1)
	c.reads <- result
	select {
	case r := <-result:
		return copy(p, r.packet), r.err
	case <-c.closed:
		return 0, io.ErrClosedPipe
	}
}

func (c *readRecordTestWire) Write(p []byte) (int, error) { return len(p), nil }
func (c *readRecordTestWire) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })

	return nil
}
func (c *readRecordTestWire) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *readRecordTestWire) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *readRecordTestWire) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
func (c *readRecordTestWire) SetWriteDeadline(time.Time) error { return nil }
func (c *readRecordTestWire) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t

	return nil
}
func (c *readRecordTestWire) readDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.deadline
}

type readRecordTestTimeout struct{}

func (*readRecordTestTimeout) Error() string   { return "unrelated transport timeout" }
func (*readRecordTestTimeout) Timeout() bool   { return true }
func (*readRecordTestTimeout) Temporary() bool { return true }
