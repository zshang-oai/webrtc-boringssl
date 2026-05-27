// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"context"
	"hash/crc32"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	ice "github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/srtp/v3"
	"github.com/pion/stun/v3"
	"github.com/pion/transport/v4/vnet"
	"github.com/stretchr/testify/require"
)

type spedHookDTLSConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr

	mu              sync.Mutex
	injectedPackets [][]byte
	injectedAddrs   []net.Addr
	outboundHook    func(packet []byte, end bool) bool
	inboundNotifier func(packet []byte)
}

func newSpedHookDTLSConn() *spedHookDTLSConn {
	return &spedHookDTLSConn{
		localAddr:  &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 10000},
		remoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 20000},
	}
}

func (c *spedHookDTLSConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c *spedHookDTLSConn) Write(packet []byte) (int, error) {
	return len(packet), nil
}

func (c *spedHookDTLSConn) Close() error {
	return nil
}

func (c *spedHookDTLSConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *spedHookDTLSConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *spedHookDTLSConn) SetDeadline(time.Time) error {
	return nil
}

func (c *spedHookDTLSConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *spedHookDTLSConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *spedHookDTLSConn) Handshake() error {
	return nil
}

func (c *spedHookDTLSConn) HandshakeContext(context.Context) error {
	return nil
}

func (c *spedHookDTLSConn) KeyingMaterialExporter() (srtp.KeyingMaterialExporter, bool) {
	return nil, false
}

func (c *spedHookDTLSConn) SelectedSRTPProtectionProfile() (dtls.SRTPProtectionProfile, bool) {
	return 0, false
}

func (c *spedHookDTLSConn) InjectInboundPacket(packet []byte, rAddr net.Addr) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.injectedPackets = append(c.injectedPackets, append([]byte(nil), packet...))
	c.injectedAddrs = append(c.injectedAddrs, rAddr)

	return nil
}

func (c *spedHookDTLSConn) SetOutboundHandshakePacketInterceptor(
	hook func(packet []byte, end bool) bool,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.outboundHook = hook
}

func (c *spedHookDTLSConn) SetInboundHandshakePacketNotifier(notify func(packet []byte)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.inboundNotifier = notify
}

func (c *spedHookDTLSConn) emitOutbound(packet []byte, end bool) bool {
	c.mu.Lock()
	hook := c.outboundHook
	c.mu.Unlock()
	if hook == nil {
		return false
	}

	return hook(packet, end)
}

func (c *spedHookDTLSConn) emitInbound(packet []byte) {
	c.mu.Lock()
	notify := c.inboundNotifier
	c.mu.Unlock()
	if notify != nil {
		notify(packet)
	}
}

func (c *spedHookDTLSConn) injected() ([][]byte, []net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()

	packets := make([][]byte, 0, len(c.injectedPackets))
	for _, packet := range c.injectedPackets {
		packets = append(packets, append([]byte(nil), packet...))
	}

	return packets, append([]net.Addr(nil), c.injectedAddrs...)
}

func newSpedICETransport(t *testing.T, api *API) *ICETransport {
	t.Helper()

	gatherer, err := api.NewICEGatherer(ICEGatherOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, gatherer.Close())
	})

	transport := api.NewICETransport(gatherer)
	require.NoError(t, transport.ensureGatherer())

	return transport
}

func newSpedAPI() *API {
	se := SettingEngine{}
	se.EnableSped(true)

	return NewAPI(WithSettingEngine(se))
}

func TestICETransportHandleDtlsPacketWaitsForCallback(t *testing.T) {
	transport := NewICETransport(nil, logging.NewDefaultLoggerFactory())
	transport.dtlsCallbackArmed = true

	packet := []byte("delayed-dtls")
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 3478}
	delivered := make(chan []byte, 1)
	returned := make(chan struct{})
	go func() {
		transport.handleDtlsPacket(packet, remoteAddr)
		close(returned)
	}()

	select {
	case <-returned:
		t.Fatal("DTLS packet returned before callback was installed")
	case <-time.After(50 * time.Millisecond):
	}

	transport.SetDtlsCallback(func(actual []byte, actualAddr net.Addr) {
		require.Equal(t, remoteAddr, actualAddr)
		delivered <- append([]byte(nil), actual...)
	})

	select {
	case actual := <-delivered:
		require.Equal(t, packet, actual)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for delayed DTLS packet callback")
	}
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for delayed DTLS packet handler")
	}
}

func TestDTLSTransportConfigureSPEDForwardsPacketsAndDeduplicatesAcks(t *testing.T) {
	api := newSpedAPI()
	iceTransport := newSpedICETransport(t, api)
	dtlsTransport, err := api.NewDTLSTransport(iceTransport, nil)
	require.NoError(t, err)

	hookConn := newSpedHookDTLSConn()
	require.NoError(t, dtlsTransport.configureSPED(hookConn))

	firstOutbound := []byte("client-flight-one")
	secondOutbound := []byte("client-flight-two")
	require.True(t, hookConn.emitOutbound(firstOutbound, false))
	require.True(t, hookConn.emitOutbound(secondOutbound, true))

	agent := iceTransport.gatherer.getAgent()
	require.NotNil(t, agent)
	packet, acks := agent.GetPiggybackDataAndAcks()
	require.Equal(t, firstOutbound, packet)
	require.Empty(t, acks)
	packet, _ = agent.GetPiggybackDataAndAcks()
	require.Equal(t, secondOutbound, packet)

	secondInbound := []byte("server-flight-two")
	firstInbound := []byte("server-flight-one")
	iceTransport.handleDtlsPacket(secondInbound, hookConn.remoteAddr)
	iceTransport.handleDtlsPacket(firstInbound, hookConn.remoteAddr)
	iceTransport.handleDtlsPacket(firstInbound, hookConn.remoteAddr)

	injected, injectedAddrs := hookConn.injected()
	require.Equal(t, [][]byte{secondInbound, firstInbound, firstInbound}, injected)
	require.Equal(t, []net.Addr{hookConn.remoteAddr, hookConn.remoteAddr, hookConn.remoteAddr}, injectedAddrs)

	hookConn.emitInbound(secondInbound)
	hookConn.emitInbound(firstInbound)
	hookConn.emitInbound(firstInbound)
	_, acks = agent.GetPiggybackDataAndAcks()
	require.Equal(t, []uint32{
		crc32.ChecksumIEEE(secondInbound),
		crc32.ChecksumIEEE(firstInbound),
	}, acks)

	dtlsTransport.clearSPED(hookConn)
	require.False(t, iceTransport.dtlsCallbackArmed)
	require.Nil(t, iceTransport.dtlsCallback)
	require.False(t, hookConn.emitOutbound([]byte("after-clear"), true))
}

func TestDTLSTransportConfigureSPEDIsNoOpWhenDisabled(t *testing.T) {
	api := NewAPI()
	iceTransport := newSpedICETransport(t, api)
	dtlsTransport, err := api.NewDTLSTransport(iceTransport, nil)
	require.NoError(t, err)

	hookConn := newSpedHookDTLSConn()
	require.NoError(t, dtlsTransport.configureSPED(hookConn))
	require.Nil(t, iceTransport.dtlsCallback)
	require.False(t, iceTransport.dtlsCallbackArmed)
	require.False(t, hookConn.emitOutbound([]byte("disabled"), true))
}

func TestPeerConnectionCanStartSCTPWhenSpedICECanWriteBeforeConnected(t *testing.T) {
	se := SettingEngine{}
	se.EnableSped(true)
	pc, err := NewAPI(WithSettingEngine(se)).NewPeerConnection(Configuration{})
	require.NoError(t, err)
	defer func() {
		require.NoError(t, pc.Close())
	}()

	conn := newSpedWritableConnBeforeNomination(t)
	pc.onICEConnectionStateChange(ICEConnectionStateChecking)
	pc.iceTransport.conn = conn
	pc.dtlsTransport.state = DTLSTransportStateConnected

	require.True(t, pc.iceTransport.CanWrite())
	require.True(t, pc.canStartSCTP())
}

func newSpedWritableConnBeforeNomination(t *testing.T) *ice.Conn {
	t.Helper()

	loggerFactory := logging.NewDefaultLoggerFactory()
	wan, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "0.0.0.0/0",
		LoggerFactory: loggerFactory,
	})
	require.NoError(t, err)

	var useCandidateRequests atomic.Uint64
	wan.AddChunkFilter(func(c vnet.Chunk) bool {
		if !stun.IsMessage(c.UserData()) {
			return true
		}

		message := &stun.Message{Raw: c.UserData()}
		if decErr := message.Decode(); decErr != nil {
			return false
		}
		if message.Contains(stun.AttrUseCandidate) {
			useCandidateRequests.Add(1)

			return false
		}

		return true
	})

	fullNet, err := vnet.NewNet(&vnet.NetConfig{
		StaticIPs: []string{"192.168.0.1", "192.168.0.3"},
	})
	require.NoError(t, err)
	require.NoError(t, wan.AddNet(fullNet))

	liteNet, err := vnet.NewNet(&vnet.NetConfig{
		StaticIPs: []string{"192.168.0.2", "192.168.0.4"},
	})
	require.NoError(t, err)
	require.NoError(t, wan.AddNet(liteNet))
	require.NoError(t, wan.Start())
	t.Cleanup(func() {
		require.NoError(t, wan.Stop())
	})

	checkInterval := 10 * time.Millisecond
	fullAgent, err := ice.NewAgent(&ice.AgentConfig{
		NetworkTypes:      []ice.NetworkType{ice.NetworkTypeUDP4},
		MulticastDNSMode:  ice.MulticastDNSModeDisabled,
		Net:               fullNet,
		CheckInterval:     &checkInterval,
		KeepaliveInterval: &checkInterval,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, fullAgent.Close())
	})

	liteAgent, err := ice.NewAgent(&ice.AgentConfig{
		NetworkTypes:      []ice.NetworkType{ice.NetworkTypeUDP4},
		CandidateTypes:    []ice.CandidateType{ice.CandidateTypeHost},
		MulticastDNSMode:  ice.MulticastDNSModeDisabled,
		Net:               liteNet,
		Lite:              true,
		CheckInterval:     &checkInterval,
		KeepaliveInterval: &checkInterval,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, liteAgent.Close())
	})

	fullAgent.SetDtlsCallback(func([]byte, net.Addr) {})
	liteAgent.SetDtlsCallback(func([]byte, net.Addr) {})
	require.True(t, fullAgent.Piggyback([]byte("client-hello"), false))

	gatherAndExchangeICECandidates(t, fullAgent, liteAgent)

	fullUfrag, fullPwd, err := fullAgent.GetLocalUserCredentials()
	require.NoError(t, err)
	liteUfrag, litePwd, err := liteAgent.GetLocalUserCredentials()
	require.NoError(t, err)

	liteConn, err := liteAgent.StartAccept(fullUfrag, fullPwd)
	require.NoError(t, err)
	_, err = fullAgent.StartDial(liteUfrag, litePwd)
	require.NoError(t, err)

	require.Eventually(t, liteConn.CanWrite, 2*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		return useCandidateRequests.Load() > 0
	}, 2*time.Second, 10*time.Millisecond)

	return liteConn
}

func gatherAndExchangeICECandidates(t *testing.T, aAgent, bAgent *ice.Agent) {
	t.Helper()

	require.NoError(t, aAgent.OnCandidate(func(candidate ice.Candidate) {
		if candidate != nil {
			require.NoError(t, bAgent.AddRemoteCandidate(candidate))
		}
	}))
	require.NoError(t, bAgent.OnCandidate(func(candidate ice.Candidate) {
		if candidate != nil {
			require.NoError(t, aAgent.AddRemoteCandidate(candidate))
		}
	}))
	require.NoError(t, aAgent.GatherCandidates())
	require.NoError(t, bAgent.GatherCandidates())
}
