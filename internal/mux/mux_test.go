// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mux

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/transport/v5/packetio"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/require"
)

const testPipeBufferSize = 8192

func TestNoEndpoints(t *testing.T) {
	// In memory pipe
	ca, cb := net.Pipe()
	require.NoError(t, cb.Close())

	mux := NewMux(Config{
		Conn:          ca,
		BufferSize:    testPipeBufferSize,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	require.NoError(t, mux.dispatch(make([]byte, 1)))
	require.NoError(t, mux.Close())
	require.NoError(t, ca.Close())
}

func TestEndpointDeadline(t *testing.T) {
	tests := []struct {
		name        string
		setDeadline func(*Endpoint, time.Time) error
	}{
		{
			name:        "SetReadDeadline",
			setDeadline: (*Endpoint).SetReadDeadline,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lim := test.TimeOut(2 * time.Second)
			defer lim.Stop()

			ca, cb := net.Pipe()
			defer func() {
				_ = ca.Close()
				_ = cb.Close()
			}()

			mux := NewMux(Config{
				Conn:          ca,
				BufferSize:    testPipeBufferSize,
				LoggerFactory: logging.NewDefaultLoggerFactory(),
			})

			endpoint := mux.NewEndpoint(MatchAll)
			require.NoError(t, tt.setDeadline(endpoint, time.Now().Add(10*time.Millisecond)))

			_, err := endpoint.Read(make([]byte, testPipeBufferSize))
			require.Error(t, err)
			var netErr interface{ Timeout() bool }
			require.ErrorAs(t, err, &netErr)
			require.True(t, netErr.Timeout())

			require.NoError(t, mux.Close())
		})
	}
}

type writeDeadlineConn struct {
	net.Conn
	writeDeadline time.Time
}

func (w *writeDeadlineConn) SetWriteDeadline(t time.Time) error {
	w.writeDeadline = t

	if w.Conn == nil {
		return nil
	}

	return w.Conn.SetWriteDeadline(t)
}

func TestEndpointSetWriteDeadline(t *testing.T) {
	lim := test.TimeOut(2 * time.Second)
	defer lim.Stop()

	ca, cb := net.Pipe()
	defer func() {
		_ = cb.Close()
	}()

	rdConn := &writeDeadlineConn{Conn: ca}

	mux := NewMux(Config{
		Conn:          rdConn,
		BufferSize:    testPipeBufferSize,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})

	endpoint := mux.NewEndpoint(MatchAll)
	deadline := time.Now().Add(10 * time.Millisecond)
	require.NoError(t, endpoint.SetWriteDeadline(deadline))
	require.WithinDuration(t, deadline, rdConn.writeDeadline, time.Millisecond)

	require.NoError(t, mux.Close())
}

type writeDeadlineErrorConn struct {
	net.Conn
	deadlineErr error
}

type writeResultConn struct {
	net.Conn
	n   int
	err error
}

func (w *writeResultConn) Write([]byte) (int, error) {
	return w.n, w.err
}

func (w *writeDeadlineErrorConn) SetDeadline(t time.Time) error {
	if w.deadlineErr != nil {
		return w.deadlineErr
	}

	return nil
}

var errDeadlineTest = errors.New("write deadline failed")

func TestEndpointSetDeadlineWriteDeadlineError(t *testing.T) {
	lim := test.TimeOut(2 * time.Second)
	defer lim.Stop()

	ca, cb := net.Pipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()

	rdConn := &writeDeadlineErrorConn{Conn: ca, deadlineErr: errDeadlineTest}

	mux := NewMux(Config{
		Conn:          rdConn,
		BufferSize:    testPipeBufferSize,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})

	endpoint := mux.NewEndpoint(MatchAll)
	err := endpoint.SetDeadline(time.Now().Add(10 * time.Millisecond))
	require.Error(t, err)
	require.ErrorIs(t, err, errDeadlineTest)

	require.NoError(t, mux.Close())
	require.NoError(t, ca.Close())
	require.NoError(t, rdConn.Close())
}

// No ICE route is packet loss for every WebRTC mux user. Only that wholly
// unsent case is accepted; other results retain their normal write semantics.
func TestEndpointWriteNoRoutePolicy(t *testing.T) {
	packet := []byte("datagram")
	for _, tc := range []struct {
		name    string
		n       int
		err     error
		wantN   int
		wantErr error
	}{
		{name: "no route", err: ice.ErrNoCandidatePairs, wantN: len(packet)},
		{name: "wrapped no route", err: fmt.Errorf("write: %w", ice.ErrNoCandidatePairs), wantN: len(packet)},
		{name: "partial no route", n: 1, err: ice.ErrNoCandidatePairs, wantN: 1, wantErr: ice.ErrNoCandidatePairs},
		{name: "ICE closed", err: ice.ErrClosed, wantErr: io.ErrClosedPipe},
		{name: "closed pipe", err: io.ErrClosedPipe, wantErr: io.ErrClosedPipe},
		{name: "deadline", err: os.ErrDeadlineExceeded, wantErr: os.ErrDeadlineExceeded},
		{name: "other error", err: io.ErrUnexpectedEOF, wantErr: io.ErrUnexpectedEOF},
		{name: "short write", n: 1, wantN: 1},
		{name: "success", n: len(packet), wantN: len(packet)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := &Endpoint{mux: &Mux{nextConn: &writeResultConn{n: tc.n, err: tc.err}}}
			for _, write := range []func([]byte) (int, error){
				endpoint.Write,
				func(p []byte) (int, error) { return endpoint.WriteTo(p, nil) },
			} {
				n, err := write(packet)
				require.Equal(t, tc.wantN, n)
				require.ErrorIs(t, err, tc.wantErr)
			}
		})
	}
}

// Observe the real ICE result below the mux: accepting a lost datagram must not
// change ICE's direct error contract or count bytes as physically sent.
func TestEndpointNoRouteUsesRealICEError(t *testing.T) {
	agent, err := ice.NewAgentWithOptions(ice.WithMulticastDNSMode(ice.MulticastDNSModeDisabled))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, agent.Close()) })
	conn, err := agent.StartDial("remote-ufrag", "remote-password")
	require.NoError(t, err)
	lower := &recordICEWriteConn{Conn: conn}
	m := NewMux(Config{Conn: lower, BufferSize: testPipeBufferSize, LoggerFactory: logging.NewDefaultLoggerFactory()})
	t.Cleanup(func() { require.NoError(t, m.Close()) })
	endpoint := m.NewEndpoint(MatchAll)
	packet := []byte("datagram")
	n, err := endpoint.Write(packet)
	require.NoError(t, err)
	require.Equal(t, len(packet), n)
	require.Zero(t, lower.n)
	require.ErrorIs(t, lower.err, ice.ErrNoCandidatePairs)
	require.Zero(t, conn.BytesSent())
}

type recordICEWriteConn struct {
	net.Conn
	n   int
	err error
}

func (c *recordICEWriteConn) Write(packet []byte) (int, error) {
	c.n, c.err = c.Conn.Write(packet)

	return c.n, c.err
}

type muxErrorConnReadResult struct {
	err  error
	data []byte
}

// muxErrorConn.
type muxErrorConn struct {
	net.Conn
	readResults []muxErrorConnReadResult
}

func (m *muxErrorConn) Read(b []byte) (n int, err error) {
	err = m.readResults[0].err
	copy(b, m.readResults[0].data)
	n = len(m.readResults[0].data)

	m.readResults = m.readResults[1:]

	return
}

/*
Don't end the mux readLoop for packetio.ErrTimeout or io.ErrShortBuffer, assert the following

  - io.ErrShortBuffer and packetio.ErrTimeout don't end the read loop

  - io.EOF ends the loop

    pion/webrtc#1720
*/
func TestNonFatalRead(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	expectedData := []byte("expectedData")

	// In memory pipe
	ca, cb := net.Pipe()
	require.NoError(t, cb.Close())

	conn := &muxErrorConn{ca, []muxErrorConnReadResult{
		// Non-fatal timeout error
		{packetio.ErrTimeout, nil},
		{nil, expectedData},
		{io.ErrShortBuffer, nil},
		{nil, expectedData},
		{io.EOF, nil},
	}}

	mux := NewMux(Config{
		Conn:          conn,
		BufferSize:    testPipeBufferSize,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})

	e := mux.NewEndpoint(MatchAll)

	buff := make([]byte, testPipeBufferSize)
	n, err := e.Read(buff)
	require.NoError(t, err)
	require.Equal(t, buff[:n], expectedData)

	n, err = e.Read(buff)
	require.NoError(t, err)
	require.Equal(t, buff[:n], expectedData)

	<-mux.closedCh
	require.NoError(t, mux.Close())
	require.NoError(t, ca.Close())
}

// If a endpoint returns packetio.ErrFull it is a non-fatal error and shouldn't cause
// the mux to be destroyed
// pion/webrtc#2180
// .
func TestNonFatalDispatch(t *testing.T) {
	in, out := net.Pipe()

	mux := NewMux(Config{
		Conn:          out,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
		BufferSize:    1500,
	})

	e := mux.NewEndpoint(MatchSRTP)
	e.buffer.SetLimitSize(1)

	for i := 0; i <= 25; i++ {
		srtpPacket := []byte{128, 1, 2, 3, 4}
		_, err := in.Write(srtpPacket)
		require.NoError(t, err)
	}

	require.NoError(t, mux.Close())
	require.NoError(t, in.Close())
	require.NoError(t, out.Close())
}

func BenchmarkDispatch(b *testing.B) {
	mux := &Mux{
		endpoints: make(map[*Endpoint]MatchFunc),
		log:       logging.NewDefaultLoggerFactory().NewLogger("mux"),
	}

	endpoint := mux.NewEndpoint(MatchSRTP)
	mux.NewEndpoint(MatchSRTCP)

	buf := []byte{128, 1, 2, 3, 4}
	buf2 := make([]byte, 1200)

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		err := mux.dispatch(buf)
		if err != nil {
			b.Errorf("dispatch: %v", err)
		}
		_, _, err = endpoint.buffer.Read(buf2, nil)
		if err != nil {
			b.Errorf("read: %v", err)
		}
	}
}

func TestPendingQueue(t *testing.T) {
	factory := logging.NewDefaultLoggerFactory()
	factory.DefaultLogLevel = logging.LogLevelDebug
	mux := &Mux{
		endpoints: make(map[*Endpoint]MatchFunc),
		log:       factory.NewLogger("mux"),
	}

	// Assert empty packets don't end up in queue
	require.NoError(t, mux.dispatch([]byte{}))
	require.Equal(t, len(mux.pendingPackets), 0)

	// Test Happy Case
	inBuffer := []byte{20, 1, 2, 3, 4}
	outBuffer := make([]byte, len(inBuffer))

	require.NoError(t, mux.dispatch(inBuffer))

	endpoint := mux.NewEndpoint(MatchDTLS)
	require.NotNil(t, endpoint)

	_, err := endpoint.Read(outBuffer)
	require.NoError(t, err)

	require.Equal(t, outBuffer, inBuffer)

	// Assert limit on pendingPackets
	for i := 0; i <= 100; i++ {
		require.NoError(t, mux.dispatch([]byte{64, 65, 66}))
	}
	require.Equal(t, len(mux.pendingPackets), maxPendingPackets)
}
