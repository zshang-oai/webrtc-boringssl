// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/pion/webrtc/v4/internal/mux"
	"github.com/stretchr/testify/require"
)

// Custom factories are not required to implement SPED, but enabling SPED must
// reject missing negotiated-version reporting before installing any hooks.
type noVersionSPEDConn struct {
	DTLSConn
	outbound func([][]byte, net.Addr) bool
	notifier func([]byte)
}

func (c *noVersionSPEDConn) SetOutboundHandshakePacketInterceptor(h func([][]byte, net.Addr) bool) {
	c.outbound = h
}
func (c *noVersionSPEDConn) SetInboundHandshakePacketNotifier(h func([]byte)) { c.notifier = h }
func (c *noVersionSPEDConn) InjectInboundPacket([]byte, net.Addr) error       { return nil }

func TestDTLSTransportConfigureSPEDRequiresNegotiatedVersion(t *testing.T) {
	api := newSpedAPI()
	iceTransport := newSpedICETransport(t, api)
	transport, err := api.NewDTLSTransport(iceTransport, nil)
	require.NoError(t, err)
	conn := &noVersionSPEDConn{DTLSConn: &noHookDTLSConn{errConn: &errConn{}}}
	require.ErrorContains(t, transport.configureSPED(conn), "negotiated version")
	require.Nil(t, conn.outbound)
	require.Nil(t, conn.notifier)
	require.Nil(t, iceTransport.dtlsCallback)
}

type contextRecordingDTLSConn struct {
	*noHookDTLSConn
	handshakeContext context.Context
	handshakeCalls   int
	err              error
}

func (c *contextRecordingDTLSConn) Handshake() error { c.handshakeCalls++; return c.err }
func (c *contextRecordingDTLSConn) HandshakeContext(ctx context.Context) error {
	c.handshakeContext = ctx
	return c.err
}

func TestDTLSTransportFactoryStartContextOwnership(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "StartUsesContextMaker"
		if explicit {
			name = "StartContextUsesCaller"
		}
		t.Run(name, func(t *testing.T) {
			wantedErr := errors.New("stop after checking handshake context")
			conn := &contextRecordingDTLSConn{noHookDTLSConn: &noHookDTLSConn{errConn: &errConn{}}, err: wantedErr}
			makerCtx, makerCancel := context.WithCancel(context.Background())
			defer makerCancel()
			callerCtx, callerCancel := context.WithCancel(context.Background())
			defer callerCancel()
			makerCalls, makerCanceled := 0, false
			se := SettingEngine{}
			se.SetDTLSFactory(testDTLSFactory{conn: conn})
			se.dtls.connectContextMaker = func() (context.Context, func()) {
				makerCalls++
				return makerCtx, func() { makerCanceled = true; makerCancel() }
			}
			api := NewAPI(WithSettingEngine(se))
			local, remote := net.Pipe()
			t.Cleanup(func() { _ = remote.Close() })
			iceTransport := api.NewICETransport(nil)
			iceTransport.mux = mux.NewMux(mux.Config{Conn: local, BufferSize: 1500, LoggerFactory: api.settingEngine.LoggerFactory})
			t.Cleanup(func() { _ = iceTransport.mux.Close() })
			transport, err := api.NewDTLSTransport(iceTransport, nil)
			require.NoError(t, err)
			if explicit {
				err = transport.StartContext(callerCtx, DTLSParameters{Role: DTLSRoleServer})
			} else {
				err = transport.Start(DTLSParameters{Role: DTLSRoleServer})
			}
			require.ErrorIs(t, err, wantedErr)
			require.Zero(t, conn.handshakeCalls, "both selected contexts must reach the factory connection's HandshakeContext")
			if explicit {
				require.Same(t, callerCtx, conn.handshakeContext)
				require.Zero(t, makerCalls)
				require.False(t, makerCanceled)
			} else {
				require.Same(t, makerCtx, conn.handshakeContext)
				require.Equal(t, 1, makerCalls)
				require.True(t, makerCanceled)
			}
		})
	}
}

func TestDTLSTransportLateStartupCannotUndoStop(t *testing.T) {
	transport, err := NewAPI().NewDTLSTransport(nil, nil)
	require.NoError(t, err)
	require.NoError(t, transport.Stop())
	require.Error(t, transport.completeStart(&noHookDTLSConn{errConn: &errConn{}}))
	require.Equal(t, DTLSTransportStateClosed, transport.State())
	require.Nil(t, transport.conn)
}

func TestDTLSTransportFailureNotificationAfterEndpointClose(t *testing.T) {
	transport, err := NewAPI().NewDTLSTransport(nil, nil)
	require.NoError(t, err)
	require.NoError(t, transport.Stop())
	var states []DTLSTransportState
	transport.OnStateChange(func(state DTLSTransportState) { states = append(states, state) })
	failed := errors.New("handshake failure after endpoint close")
	require.ErrorIs(t, transport.failStart(failed), failed)
	require.Equal(t, []DTLSTransportState{DTLSTransportStateFailed}, states)
	require.Nil(t, transport.conn, "a failure notification does not install a live connection")
}
