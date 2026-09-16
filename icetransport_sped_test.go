// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/transport/v5/vnet"
	"github.com/stretchr/testify/require"
)

func TestICETransportSPEDStopReleasesEarlyCallback(t *testing.T) {
	for _, graceful := range []bool{false, true} {
		name := "Stop"
		if graceful {
			name = "GracefulStop"
		}
		t.Run(name, func(t *testing.T) {
			transport := NewICETransport(nil, logging.NewDefaultLoggerFactory())
			transport.dtlsCallbackArmed = true
			returned := make(chan struct{})
			go func() { transport.handleDtlsPacket(spedTestRecord("early"), &net.UDPAddr{}); close(returned) }()
			select {
			case <-returned:
				t.Fatal("early callback returned before a consumer was installed")
			case <-time.After(25 * time.Millisecond):
			}
			if graceful {
				require.NoError(t, transport.GracefulStop())
			} else {
				require.NoError(t, transport.Stop())
			}
			select {
			case <-returned:
			case <-time.After(time.Second):
				t.Fatal("Stop did not release the early callback")
			}
		})
	}
}

// The callback below is reached by an authenticated STUN request, on the real
// ICE task loop. Stop joins that loop, so it must release the callback first.
func TestICETransportSPEDStopReleasesEarlyCallbackOnWire(t *testing.T) {
	for _, graceful := range []bool{false, true} {
		name := "Stop"
		if graceful {
			name = "GracefulStop"
		}
		t.Run(name, func(t *testing.T) {
			transport, full, lite, params := newLiteSPEDTransportPair(t)
			role := ICERoleControlled
			require.NoError(t, transport.Start(nil, params, &role))
			reached := make(chan struct{})
			var once sync.Once
			lite.SetDtlsCallback(func(packet []byte, addr net.Addr) {
				once.Do(func() { close(reached) })
				transport.handleDtlsPacket(packet, addr)
			})
			full.SetDtlsCallback(func([]byte, net.Addr) {})
			require.True(t, full.Piggyback([][]byte{spedTestRecord("client-hello")}, nil))
			u, p, err := lite.GetLocalUserCredentials()
			require.NoError(t, err)
			_, err = full.StartDial(u, p)
			require.NoError(t, err)
			select {
			case <-reached:
			case <-time.After(2 * time.Second):
				t.Fatal("no authenticated embedded DTLS callback")
			}
			stopped := make(chan error, 1)
			go func() {
				if graceful {
					stopped <- transport.GracefulStop()
				} else {
					stopped <- transport.Stop()
				}
			}()
			select {
			case err := <-stopped:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("Stop blocked on the early SPED callback")
			}
		})
	}
}

// Real queued ICE notifications can overwrite the reported Closed state after
// Stop. They must not revive the owner's irreversible startup/callback latch.
func TestICETransportSPEDQueuedStateCannotRearmStop(t *testing.T) {
	transport, full, lite, params := newLiteSPEDTransportPair(t)
	checking, connected := make(chan struct{}), make(chan struct{})
	releaseChecking, releaseConnected := make(chan struct{}), make(chan struct{})
	var checkingOnce, connectedOnce, releaseCheckingOnce, releaseConnectedOnce sync.Once
	t.Cleanup(func() {
		releaseCheckingOnce.Do(func() { close(releaseChecking) })
		releaseConnectedOnce.Do(func() { close(releaseConnected) })
	})
	transport.OnConnectionStateChange(func(state ICETransportState) {
		switch state {
		case ICETransportStateChecking:
			checkingOnce.Do(func() { close(checking) })
			<-releaseChecking
		case ICETransportStateConnected:
			connectedOnce.Do(func() { close(connected) })
			<-releaseConnected
		}
	})
	role := ICERoleControlled
	require.NoError(t, transport.Start(nil, params, &role))
	select {
	case <-checking:
	case <-time.After(time.Second):
		t.Fatal("Checking notification not delivered")
	}
	u, p, err := lite.GetLocalUserCredentials()
	require.NoError(t, err)
	_, err = full.StartDial(u, p)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, full.AwaitConnect(ctx))
	require.Eventually(t, func() bool { pair, err := lite.GetSelectedCandidatePair(); return err == nil && pair != nil }, time.Second, time.Millisecond)
	require.NoError(t, transport.Stop())
	require.Equal(t, ICETransportStateClosed, transport.State())
	releaseCheckingOnce.Do(func() { close(releaseChecking) })
	select {
	case <-connected:
	case <-time.After(time.Second):
		t.Fatal("queued Connected notification not delivered")
	}
	require.Equal(t, ICETransportStateConnected, transport.State())
	transport.SetDtlsCallback(func([]byte, net.Addr) {})
	transport.lock.RLock()
	armed, cb := transport.dtlsCallbackArmed, transport.dtlsCallback
	transport.lock.RUnlock()
	require.False(t, armed)
	require.Nil(t, cb)
	require.ErrorIs(t, transport.Start(nil, params, &role), errICETransportClosed)
}

func TestICETransportSPEDStartContextAlreadyCanceled(t *testing.T) {
	se := SettingEngine{}
	se.EnableSped(true)
	api := NewAPI(WithSettingEngine(se))
	g, err := api.NewICEGatherer(ICEGatherOptions{})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, g.Close()) })
	transport := api.NewICETransport(g)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	role := ICERoleControlled
	err = transport.StartContext(ctx, nil, ICEParameters{UsernameFragment: "remote-ufrag", Password: "remote-password-long-enough"}, &role)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, ICEGathererStateClosed, g.State())
	require.False(t, transport.dtlsCallbackArmed)
	require.Nil(t, transport.ctxCancel)
}

func TestICETransportSPEDStartContextCancellationAfterReturnDoesNotStop(t *testing.T) {
	transport, _, _, params := newLiteSPEDTransportPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	role := ICERoleControlled
	require.NoError(t, transport.StartContext(ctx, nil, params, &role))
	cancel()
	// Cancellation owns startup, not the established transport. This includes
	// SPED's deliberately early return before nomination.
	require.Never(t, func() bool { transport.lock.RLock(); defer transport.lock.RUnlock(); return transport.stopped }, 50*time.Millisecond, time.Millisecond)
	transport.lock.RLock()
	defer transport.lock.RUnlock()
	require.NotNil(t, transport.conn)
	require.NotNil(t, transport.mux)
}

func TestICETransportSPEDRoleErrorDisarmsCallback(t *testing.T) {
	transport, _, _, params := newLiteSPEDTransportPair(t)
	role := ICERoleUnknown
	require.ErrorIs(t, transport.StartContext(context.Background(), nil, params, &role), errICERoleUnknown)
	require.Nil(t, transport.ctxCancel)
	require.False(t, transport.dtlsCallbackArmed)
	require.Nil(t, transport.dtlsCallback)
	require.False(t, transport.stopped)
}

func newLiteSPEDTransportPair(t *testing.T) (*ICETransport, *ice.Agent, *ice.Agent, ICEParameters) {
	t.Helper()
	logger := logging.NewDefaultLoggerFactory()
	wan, err := vnet.NewRouter(&vnet.RouterConfig{CIDR: "0.0.0.0/0", LoggerFactory: logger})
	require.NoError(t, err)
	fullNet, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{"192.168.0.1"}})
	require.NoError(t, err)
	liteNet, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{"192.168.0.2"}})
	require.NoError(t, err)
	require.NoError(t, wan.AddNet(fullNet))
	require.NoError(t, wan.AddNet(liteNet))
	require.NoError(t, wan.Start())
	t.Cleanup(func() { require.NoError(t, wan.Stop()) })
	interval := 10 * time.Millisecond
	full, err := ice.NewAgent(&ice.AgentConfig{NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4}, CandidateTypes: []ice.CandidateType{ice.CandidateTypeHost}, MulticastDNSMode: ice.MulticastDNSModeDisabled, Net: fullNet, CheckInterval: &interval})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, full.Close()) })
	se := SettingEngine{}
	se.EnableSped(true)
	se.SetLite(true)
	se.SetNet(liteNet)
	se.SetNetworkTypes([]NetworkType{NetworkTypeUDP4})
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	api := NewAPI(WithSettingEngine(se))
	g, err := api.NewICEGatherer(ICEGatherOptions{})
	require.NoError(t, err)
	transport := api.NewICETransport(g)
	require.NoError(t, transport.ensureGatherer())
	t.Cleanup(func() {
		// Also release a waiter if an assertion fails before normal Stop. This is
		// test cleanup, not an alternate production shutdown path.
		transport.lock.Lock()
		transport.disarmDtlsCallbackLocked()
		transport.lock.Unlock()
		require.NoError(t, transport.Stop())
		require.NoError(t, g.Close())
	})
	lite := g.getAgent()
	gatherAndExchangeICECandidates(t, full, lite)
	u, p, err := full.GetLocalUserCredentials()
	require.NoError(t, err)
	return transport, full, lite, ICEParameters{UsernameFragment: u, Password: p}
}
