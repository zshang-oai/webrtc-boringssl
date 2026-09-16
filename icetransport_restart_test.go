// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Wait for the exact operation to enter the real agent loop, rather than hoping
// a goroutine has acquired its locks after a sleep. The callback below keeps the
// loop occupied, so this stack cannot disappear before the test releases it.
func waitForICEOperationOnTaskLoop(t *testing.T, method string) {
	t.Helper()
	buffer := make([]byte, 1<<20)
	require.Eventually(t, func() bool {
		stack := string(buffer[:runtime.Stack(buffer, true)])
		for goroutine := range strings.SplitSeq(stack, "\n\n") {
			if strings.Contains(goroutine, "(*ICETransport)."+method+"(") &&
				strings.Contains(goroutine, "internal/taskloop.(*Loop).Run(") {
				return true
			}
		}

		return false
	}, 2*time.Second, time.Millisecond, "transport operation did not reach ICE task loop: %s", method)
}

// The callback comes from an authenticated STUN packet on the real agent loop.
// The TryLock check makes the old lock inversion fail without deadlocking test
// cleanup: if the waiting operation owns the lock, return to unblock that loop.
func gatedICERestartCallback(t *testing.T) (*ICETransport, ICEParameters, func(), <-chan bool) {
	t.Helper()
	transport, full, lite, params := newLiteSPEDTransportPair(t)
	role := ICERoleControlled
	require.NoError(t, transport.Start(nil, params, &role))
	transport.SetDtlsCallback(func([]byte, net.Addr) {})
	reached, release := make(chan struct{}), make(chan struct{})
	lockAvailable := make(chan bool, 1)
	var callbackOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	lite.SetDtlsCallback(func(packet []byte, addr net.Addr) {
		callbackOnce.Do(func() {
			close(reached)
			<-release
			available := transport.lock.TryLock()
			if available {
				transport.lock.Unlock()
				transport.handleDtlsPacket(packet, addr)
			}
			lockAvailable <- available
		})
	})
	full.SetDtlsCallback(func([]byte, net.Addr) {})
	username, password, err := lite.GetLocalUserCredentials()
	require.NoError(t, err)
	require.True(t, full.Piggyback([][]byte{spedTestRecord("restart-callback")}, nil))
	_, err = full.StartDial(username, password)
	require.NoError(t, err)
	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "authenticated ICE callback was not delivered")
	}

	return transport, params, unblock, lockAvailable
}

func TestICETransportAgentOperationsReleaseLockForSPEDCallback(t *testing.T) {
	for _, method := range []string{
		"restart", "GetRemoteParameters", "haveRemoteCredentialsChange", "setRemoteCredentials",
	} {
		t.Run(method, func(t *testing.T) {
			transport, params, unblock, lockAvailable := gatedICERestartCallback(t)
			done := make(chan error, 1)
			go func() {
				switch method {
				case "restart":
					done <- transport.restart()
				case "GetRemoteParameters":
					_, err := transport.GetRemoteParameters()
					done <- err
				case "haveRemoteCredentialsChange":
					transport.haveRemoteCredentialsChange(params.UsernameFragment, params.Password)
					done <- nil
				case "setRemoteCredentials":
					done <- transport.setRemoteCredentials(params.UsernameFragment, params.Password)
				}
			}()
			waitForICEOperationOnTaskLoop(t, method)
			unblock()
			select {
			case available := <-lockAvailable:
				require.True(t, available, "operation retained transport lock while waiting for callback's ICE loop")
			case <-time.After(2 * time.Second):
				require.FailNow(t, "ICE callback did not finish")
			}
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(2 * time.Second):
				require.FailNow(t, "transport operation did not finish after ICE callback")
			}
		})
	}
}

func TestICETransportStopCancelsRestartWaitingForSPEDCallback(t *testing.T) {
	transport, params, unblock, lockAvailable := gatedICERestartCallback(t)
	restarted, stopped := make(chan error, 1), make(chan error, 1)
	go func() { restarted <- transport.restart() }()
	waitForICEOperationOnTaskLoop(t, "restart")
	go func() { stopped <- transport.Stop() }()
	// Stop must mark the loop closed and release the pending Restart before the
	// callback returns; its disarmed callback must never re-create a transport.
	select {
	case err := <-restarted:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		unblock()
		require.FailNow(t, "Stop did not cancel Restart while the ICE callback was blocked")
	}
	unblock()
	select {
	case available := <-lockAvailable:
		require.True(t, available)
	case <-time.After(2 * time.Second):
		require.FailNow(t, "stopped ICE callback did not finish")
	}
	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		require.FailNow(t, "Stop did not finish after the ICE callback")
	}
	require.False(t, transport.CanWrite())
	require.ErrorIs(t, transport.restart(), errICETransportClosed)
	role := ICERoleControlled
	require.ErrorIs(t, transport.Start(nil, params, &role), errICETransportClosed)
}
