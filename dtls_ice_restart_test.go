// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build boringssl && cgo && !js

package webrtc

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/transport/v5/vnet"
	"github.com/pion/webrtc/v4/internal/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errUnexpectedRestartTestConn = errors.New("unexpected restart test connection")

// These barriers alter only scheduling. During a controlled route outage, the
// probe checks the real ICE error separately from the DTLS endpoint write: ICE
// must report no route, while the mux accepts the datagram without sending bytes.
type restartWriteGate struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	resume  sync.Once
}

func newRestartWriteGate() *restartWriteGate {
	return &restartWriteGate{entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *restartWriteGate) wait() {
	if g != nil {
		g.once.Do(func() {
			close(g.entered)
			<-g.release
		})
	}
}

func (g *restartWriteGate) unblock() {
	if g != nil {
		g.resume.Do(func() { close(g.release) })
	}
}

type restartProbeConn struct {
	net.Conn
	gate      *restartWriteGate
	transport *ICETransport
	noRoute   chan struct{}
	once      sync.Once
}

func (c *restartProbeConn) Write(packet []byte) (int, error) {
	c.gate.wait()
	c.transport.lock.RLock()
	raw := c.transport.conn
	c.transport.lock.RUnlock()

	// Restart signaling stays paused until this observation, so no new route
	// can appear during the controlled outage. The empty probe observes ICE's
	// real error; it does not stand in for the following DTLS datagram write.
	before := raw.BytesSent()
	noRoute := false
	if !raw.CanWrite() {
		probeN, probeErr := raw.Write(nil)
		noRoute = probeN == 0 && errors.Is(probeErr, ice.ErrNoCandidatePairs)
	}
	n, err := c.Conn.Write(packet)
	if noRoute && !raw.CanWrite() && raw.BytesSent() == before && n == len(packet) && err == nil {
		c.once.Do(func() { close(c.noRoute) })
	}

	return n, err
}

func (c *restartProbeConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	n, err := c.Read(packet)

	return n, nil, err
}

func (c *restartProbeConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	return c.Write(packet)
}

type restartRecordingFactory struct {
	t         *testing.T
	native    bool
	wire      *restartWriteGate
	app       *restartWriteGate
	transport *ICETransport
	noRoute   chan struct{}
	injected  atomic.Uint64
}

//nolint:staticcheck // DTLSFactory requires the legacy config interface.
func (f *restartRecordingFactory) Client(conn net.PacketConn, addr net.Addr, cfg *dtls.Config) (DTLSConn, error) {
	return f.recordCreation(f.create(conn, addr, cfg, true))
}

//nolint:staticcheck // DTLSFactory requires the legacy config interface.
func (f *restartRecordingFactory) Server(conn net.PacketConn, addr net.Addr, cfg *dtls.Config) (DTLSConn, error) {
	return f.recordCreation(f.create(conn, addr, cfg, false))
}

func (f *restartRecordingFactory) recordCreation(conn DTLSConn, err error) (DTLSConn, error) {
	assert.NoError(f.t, err, "restart DTLS factory (native=%t)", f.native)

	return conn, err
}

//nolint:staticcheck // Exercise the DTLSFactory config contract for both implementations.
func (f *restartRecordingFactory) create(
	conn net.PacketConn, addr net.Addr, cfg *dtls.Config, client bool,
) (DTLSConn, error) {
	endpoint, ok := conn.(*mux.Endpoint)
	if !ok {
		return nil, fmt.Errorf("%w: expected mux endpoint, got %T", errUnexpectedRestartTestConn, conn)
	}
	probe := &restartProbeConn{Conn: endpoint, gate: f.wire, transport: f.transport, noRoute: f.noRoute}
	if f.native {
		factory := NewBoringSSLFactory()
		var result DTLSConn
		var err error
		if client {
			result, err = factory.Client(conn, addr, cfg)
		} else {
			result, err = factory.Server(conn, addr, cfg)
		}
		if err != nil {
			return result, err
		}
		nativeConn, ok := result.(*boringSSLConn)
		if !ok {
			return nil, fmt.Errorf("%w: expected native connection, got %T", errUnexpectedRestartTestConn, result)
		}

		// Exercise the normal factory's endpoint conversion first, including a
		// nil remote address before nomination. No I/O starts until Handshake.
		probe.Conn = nativeConn.Conn
		nativeConn.Conn = probe

		return &restartApplicationGateConn{
			boringSSLConn: nativeConn, gate: f.app, injected: &f.injected,
		}, nil
	}
	var result *dtls.Conn
	var err error
	if client {
		result, err = dtls.Client(probe, addr, cfg)
	} else {
		result, err = dtls.Server(probe, addr, cfg)
	}
	if err != nil {
		return nil, err
	}

	return &pionDTLSConn{Conn: result}, nil
}

// Embedding the concrete native connection preserves SPED's optional packet
// hooks and close-notify callback while pausing the first SCTP application write.
type restartApplicationGateConn struct {
	*boringSSLConn
	gate     *restartWriteGate
	injected *atomic.Uint64
}

func (c *restartApplicationGateConn) Write(packet []byte) (int, error) {
	c.gate.wait()

	return c.boringSSLConn.Write(packet)
}

func (c *restartApplicationGateConn) InjectInboundPacket(packet []byte, addr net.Addr) error {
	if len(packet) > 0 && !c.handshakeComplete.Load() {
		c.injected.Add(1)
	}

	return c.boringSSLConn.InjectInboundPacket(packet, addr)
}

type restartPayloadPair struct {
	offer, answer                 *PeerConnection
	offerDC, answerDC             *DataChannel
	offerReceived, answerReceived chan string
	offerOpened, answerOpened     chan struct{}
	drop                          atomic.Bool
	closed                        atomic.Bool
}

func newRestartPayloadPair(
	t *testing.T, offerFactory, answerFactory *restartRecordingFactory, sped, snap bool,
) *restartPayloadPair {
	t.Helper()
	pair := &restartPayloadPair{
		offerReceived: make(chan string, 16), answerReceived: make(chan string, 16),
		offerOpened: make(chan struct{}), answerOpened: make(chan struct{}),
	}
	const restartSubnet = "1.2.3.0/24"
	router, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR: restartSubnet, LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	require.NoError(t, err)
	router.AddChunkFilter(func(vnet.Chunk) bool { return !pair.drop.Load() })
	newPC := func(ip string, factory *restartRecordingFactory, role DTLSRole) *PeerConnection {
		factory.t = t
		vnet, netErr := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{ip}})
		require.NoError(t, netErr)
		require.NoError(t, router.AddNet(vnet))
		engine := SettingEngine{}
		engine.SetNet(vnet)
		engine.SetNetworkTypes([]NetworkType{NetworkTypeUDP4})
		engine.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
		engine.SetICETimeouts(300*time.Millisecond, 300*time.Millisecond, 50*time.Millisecond)
		if !factory.native {
			engine.SetDTLSRetransmissionInterval(50 * time.Millisecond)
		}
		engine.SetDTLSInsecureSkipHelloVerify(true)
		engine.SetSCTPRTOMax(200 * time.Millisecond)
		engine.EnableSped(sped)
		engine.EnableSctpSnap(snap)
		engine.SetDTLSFactory(factory)
		require.NoError(t, engine.SetAnsweringDTLSRole(role))
		pc, pcErr := NewAPI(WithSettingEngine(engine)).NewPeerConnection(Configuration{})
		require.NoError(t, pcErr)
		factory.transport = pc.iceTransport
		pc.OnConnectionStateChange(func(state PeerConnectionState) {
			if state == PeerConnectionStateClosed {
				pair.closed.Store(true)
			}
		})

		return pc
	}
	pair.offer = newPC("1.2.3.4", offerFactory, DTLSRoleServer)
	pair.answer = newPC("1.2.3.5", answerFactory, DTLSRoleClient)
	require.NoError(t, router.Start())
	t.Cleanup(func() {
		for _, factory := range []*restartRecordingFactory{offerFactory, answerFactory} {
			factory.wire.unblock()
			factory.app.unblock()
		}
		_ = pair.offer.Close()
		_ = pair.answer.Close()
		_ = router.Stop()
	})
	id, negotiated := uint16(0), true
	options := &DataChannelInit{ID: &id, Negotiated: &negotiated}
	pair.offerDC, err = pair.offer.CreateDataChannel("restart-payload", options)
	require.NoError(t, err)
	pair.answerDC, err = pair.answer.CreateDataChannel("restart-payload", options)
	require.NoError(t, err)
	pair.offerDC.OnOpen(func() { close(pair.offerOpened) })
	pair.answerDC.OnOpen(func() { close(pair.answerOpened) })
	pair.offerDC.OnMessage(func(message DataChannelMessage) { pair.offerReceived <- string(message.Data) })
	pair.answerDC.OnMessage(func(message DataChannelMessage) { pair.answerReceived <- string(message.Data) })

	return pair
}

func restartWait(t *testing.T, done <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		require.FailNow(t, "timed out waiting for "+description)
	}
}

func restartReceive(t *testing.T, received <-chan string, want string) {
	t.Helper()
	select {
	case actual := <-received:
		require.Equal(t, want, actual)
	case <-time.After(8 * time.Second):
		require.FailNowf(t, "timed out waiting for payload", "%q", want)
	}
}

func restartSignal(t *testing.T, offerer, answerer *PeerConnection, offer SessionDescription) {
	t.Helper()
	gathered := GatheringCompletePromise(offerer)
	require.NoError(t, offerer.SetLocalDescription(offer))
	restartWait(t, gathered, "offer candidates")
	require.NoError(t, answerer.SetRemoteDescription(*offerer.LocalDescription()))
	answer, err := answerer.CreateAnswer(nil)
	require.NoError(t, err)
	gathered = GatheringCompletePromise(answerer)
	require.NoError(t, answerer.SetLocalDescription(answer))
	restartWait(t, gathered, "answer candidates")
	require.NoError(t, offerer.SetRemoteDescription(*answerer.LocalDescription()))
}

func (p *restartPayloadPair) start(t *testing.T) {
	t.Helper()
	offer, err := p.offer.CreateOffer(nil)
	require.NoError(t, err)
	restartSignal(t, p.offer, p.answer, offer)
}

func (p *restartPayloadPair) opened(t *testing.T) {
	t.Helper()
	restartWait(t, p.offerOpened, "offer data channel open")
	restartWait(t, p.answerOpened, "answer data channel open")
}

func (p *restartPayloadPair) exchange(t *testing.T, prefix string) {
	t.Helper()
	require.NoError(t, p.offerDC.SendText(prefix+"-offer"))
	require.NoError(t, p.answerDC.SendText(prefix+"-answer"))
	restartReceive(t, p.answerReceived, prefix+"-offer")
	restartReceive(t, p.offerReceived, prefix+"-answer")
	require.False(t, p.closed.Load(), "ICE restart must retain the PeerConnections")
}

func restartDTLSConnection(pc *PeerConnection) DTLSConn {
	pc.dtlsTransport.lock.RLock()
	defer pc.dtlsTransport.lock.RUnlock()

	return pc.dtlsTransport.conn
}

func restartRequireNoPriorRouteLoss(t *testing.T, factories ...*restartRecordingFactory) {
	t.Helper()
	for _, factory := range factories {
		select {
		case <-factory.noRoute:
			require.FailNow(t, "no-route was already observed before the controlled restart/outage")
		default:
		}
	}
}

type restartFactoryMode struct {
	name                      string
	offerNative, answerNative bool
}

func restartFactoryModes() []restartFactoryMode {
	return []restartFactoryMode{
		{"pion", false, false},
		{"native", true, true},
		{"native-offer-pion-answer", true, false},
		{"pion-offer-native-answer", false, true},
	}
}

func TestDTLSICERestartDuringHandshakeDeliversPayload(t *testing.T) {
	for _, mode := range restartFactoryModes() {
		t.Run(mode.name, func(t *testing.T) {
			gate := newRestartWriteGate()
			offerFactory := &restartRecordingFactory{native: mode.offerNative, noRoute: make(chan struct{})}
			answerFactory := &restartRecordingFactory{native: mode.answerNative, wire: gate, noRoute: make(chan struct{})}
			pair := newRestartPayloadPair(t, offerFactory, answerFactory, false, false)
			pair.start(t)
			restartWait(t, gate.entered, "initial client DTLS write")
			offer, err := pair.answer.CreateOffer(&OfferOptions{ICERestart: true})
			require.NoError(t, err)
			require.False(t, pair.answer.iceTransport.CanWrite())
			gate.unblock()
			restartWait(t, answerFactory.noRoute, "DTLS handshake write accepted without an ICE route")
			restartSignal(t, pair.answer, pair.offer, offer)
			pair.opened(t)
			pair.exchange(t, "after-initial-restart")
		})
	}
}

func TestDTLSICERestartAfterFailedDeliversQueuedPayload(t *testing.T) {
	for _, mode := range restartFactoryModes() {
		t.Run(mode.name, func(t *testing.T) {
			offerFactory := &restartRecordingFactory{native: mode.offerNative, noRoute: make(chan struct{})}
			answerFactory := &restartRecordingFactory{native: mode.answerNative, noRoute: make(chan struct{})}
			pair := newRestartPayloadPair(t, offerFactory, answerFactory, false, false)
			pair.start(t)
			pair.opened(t)
			pair.exchange(t, "before")
			restartRequireNoPriorRouteLoss(t, offerFactory, answerFactory)
			offerDTLS, answerDTLS := restartDTLSConnection(pair.offer), restartDTLSConnection(pair.answer)
			offerSCTP, answerSCTP := pair.offer.sctpTransport.association(), pair.answer.sctpTransport.association()
			pair.drop.Store(true)
			require.Eventually(t, func() bool {
				return pair.offer.ICEConnectionState() == ICEConnectionStateFailed &&
					pair.answer.ICEConnectionState() == ICEConnectionStateFailed
			}, 5*time.Second, 10*time.Millisecond)
			require.False(t, pair.offer.iceTransport.CanWrite())
			require.False(t, pair.answer.iceTransport.CanWrite())
			require.NoError(t, pair.offerDC.SendText("during-outage-offer"))
			require.NoError(t, pair.answerDC.SendText("during-outage-answer"))
			restartWait(t, offerFactory.noRoute, "offer write accepted without a route before restart signaling")
			restartWait(t, answerFactory.noRoute, "answer write accepted without a route before restart signaling")
			pair.drop.Store(false)
			offer, err := pair.offer.CreateOffer(&OfferOptions{ICERestart: true})
			require.NoError(t, err)
			restartSignal(t, pair.offer, pair.answer, offer)
			restartReceive(t, pair.answerReceived, "during-outage-offer")
			restartReceive(t, pair.offerReceived, "during-outage-answer")
			pair.exchange(t, "after")
			require.Same(t, offerDTLS, restartDTLSConnection(pair.offer))
			require.Same(t, answerDTLS, restartDTLSConnection(pair.answer))
			require.Same(t, offerSCTP, pair.offer.sctpTransport.association())
			require.Same(t, answerSCTP, pair.answer.sctpTransport.association())
		})
	}
}

// SNAP can start with application data instead of an in-band SCTP handshake.
// Keep the startup gate intact, then remove the route immediately after it has
// allowed the first SCTP write. The real lost datagram must be retransmitted.
func TestDTLSICERestartSPEDSNAPFirstWriteDeliversPayload(t *testing.T) {
	gate := newRestartWriteGate()
	offerFactory := &restartRecordingFactory{native: true, noRoute: make(chan struct{})}
	answerFactory := &restartRecordingFactory{native: true, app: gate, noRoute: make(chan struct{})}
	pair := newRestartPayloadPair(t, offerFactory, answerFactory, true, true)
	pair.start(t)
	require.Contains(t, pair.offer.LocalDescription().SDP, "a=sctp-init:")
	require.Contains(t, pair.answer.LocalDescription().SDP, "a=sctp-init:")
	// Negotiated SNAP channels may open without producing a transport write, so
	// enqueue the first user payload as soon as their channel opens.
	restartWait(t, pair.answerOpened, "SNAP answer data channel open")
	require.NoError(t, pair.answerDC.SendText("first-snap-payload"))
	restartWait(t, gate.entered, "first SNAP application write")
	require.Equal(t, DTLSTransportStateConnected, pair.answer.dtlsTransport.State())
	require.Positive(t, offerFactory.injected.Load()+answerFactory.injected.Load(), "observe actual SPED input")
	restartRequireNoPriorRouteLoss(t, offerFactory, answerFactory)
	offer, err := pair.answer.CreateOffer(&OfferOptions{ICERestart: true})
	require.NoError(t, err)
	require.False(t, pair.answer.iceTransport.CanWrite())
	gate.unblock()
	restartWait(t, answerFactory.noRoute, "first SNAP write accepted and lost during real ICE restart")
	restartSignal(t, pair.answer, pair.offer, offer)
	pair.opened(t)
	restartReceive(t, pair.offerReceived, "first-snap-payload")
	pair.exchange(t, "after-snap-restart")
}
