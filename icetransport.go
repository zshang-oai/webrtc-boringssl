// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/webrtc/v4/internal/mux"
	"github.com/pion/webrtc/v4/internal/util"
)

// ICETransport allows an application access to information about the ICE
// transport over which packets are sent and received.
type ICETransport struct {
	lock sync.RWMutex
	// Serialize Restart and Gather without holding the lock needed by SPED callbacks.
	restartMu sync.Mutex

	role ICERole

	onConnectionStateChangeHandler         atomic.Value // func(ICETransportState)
	internalOnConnectionStateChangeHandler atomic.Value // func(ICETransportState)
	onSelectedCandidatePairChangeHandler   atomic.Value // func(*ICECandidatePair)

	state atomic.Value // ICETransportState

	gatherer *ICEGatherer
	conn     *ice.Conn
	mux      *mux.Mux

	ctxCancel func()
	stopped   bool // Protected by lock; unlike state, never changed by queued ICE notifications.

	loggerFactory logging.LoggerFactory

	dtlsCallback      func(packet []byte, rAddr net.Addr)
	dtlsCallbackCond  *sync.Cond
	dtlsCallbackArmed bool

	log logging.LeveledLogger
}

// GetSelectedCandidatePair returns the selected candidate pair on which packets are sent
// if there is no selected pair nil is returned.
func (t *ICETransport) GetSelectedCandidatePair() (*ICECandidatePair, error) {
	agent := t.gatherer.getAgent()
	if agent == nil {
		return nil, nil //nolint:nilnil
	}

	icePair, err := agent.GetSelectedCandidatePair()
	if icePair == nil || err != nil {
		return nil, err
	}

	local, err := newICECandidateFromICE(icePair.Local, "", 0)
	if err != nil {
		return nil, err
	}

	remote, err := newICECandidateFromICE(icePair.Remote, "", 0)
	if err != nil {
		return nil, err
	}

	return NewICECandidatePair(&local, &remote), nil
}

// GetSelectedCandidatePairStats returns the selected candidate pair stats on which packets are sent
// if there is no selected pair, false is returned to indicate stats are not available.
func (t *ICETransport) GetSelectedCandidatePairStats() (ICECandidatePairStats, bool) {
	return t.gatherer.getSelectedCandidatePairStats()
}

// NewICETransport creates a new NewICETransport.
func NewICETransport(gatherer *ICEGatherer, loggerFactory logging.LoggerFactory) *ICETransport {
	iceTransport := &ICETransport{
		gatherer:      gatherer,
		loggerFactory: loggerFactory,
		log:           loggerFactory.NewLogger("ortc"),
	}
	iceTransport.dtlsCallbackCond = sync.NewCond(&iceTransport.lock)
	iceTransport.setState(ICETransportStateNew)

	return iceTransport
}

// Start incoming connectivity checks based on its configured role.
func (t *ICETransport) Start(gatherer *ICEGatherer, params ICEParameters, role *ICERole) error {
	return t.StartContext(context.Background(), gatherer, params, role)
}

// StartContext incoming connectivity checks based on its configured role.
// If the context is canceled, the ICE transport will stop.
//
//nolint:cyclop
func (t *ICETransport) StartContext(
	ctx context.Context,
	gatherer *ICEGatherer,
	params ICEParameters,
	role *ICERole,
) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.stopped {
		return errICETransportClosed
	}
	if t.State() != ICETransportStateNew {
		return errICETransportNotInNew
	}

	if gatherer != nil {
		t.gatherer = gatherer
	}

	if err := t.ensureGatherer(); err != nil {
		return err
	}

	agent := t.gatherer.getAgent()
	if agent == nil {
		return fmt.Errorf("%w: unable to start ICETransport", errICEAgentNotExist)
	}
	if t.gatherer.api.settingEngine.enableSped {
		agent.SetDtlsCallback(t.handleDtlsPacket)
		t.dtlsCallbackArmed = true
	} else {
		agent.SetDtlsCallback(t.dtlsCallback)
	}

	if err := agent.OnConnectionStateChange(func(iceState ice.ConnectionState) {
		state := newICETransportStateFromICE(iceState)

		t.setState(state)
		t.onConnectionStateChange(state)
	}); err != nil {
		return err
	}
	if err := agent.OnSelectedCandidatePairChange(func(local, remote ice.Candidate) {
		candidates, err := newICECandidatesFromICE([]ice.Candidate{local, remote}, "", 0)
		if err != nil {
			t.log.Warnf("%w: %s", errICECandiatesCoversionFailed, err)

			return
		}
		t.onSelectedCandidatePairChange(NewICECandidatePair(&candidates[0], &candidates[1]))
	}); err != nil {
		return err
	}
	if err := agent.SetRemoteICELite(params.ICELite); err != nil {
		return err
	}

	if role == nil {
		controlled := ICERoleControlled
		role = &controlled
	}
	t.role = *role

	callerCtx := ctx
	operationCtx, ctxCancel := context.WithCancel(callerCtx)
	t.ctxCancel = ctxCancel
	sped := t.gatherer.api.settingEngine.enableSped
	// StartDial/StartAccept do not wait for nomination. Observe cancellation
	// during startup even when SPED skips AwaitConnect, but do not make the
	// caller's context own the established transport after StartContext returns.
	if callerCtx.Done() != nil {
		stopCancelWatch := context.AfterFunc(callerCtx, func() { _ = t.Stop() })
		defer stopCancelWatch()
	}

	// Drop the lock so candidate delivery and Stop can make progress.
	t.lock.Unlock()

	var iceConn *ice.Conn
	var err error
	if err = operationCtx.Err(); err == nil {
		switch *role {
		case ICERoleControlling:
			iceConn, err = agent.StartDial(params.UsernameFragment, params.Password)
		case ICERoleControlled:
			iceConn, err = agent.StartAccept(params.UsernameFragment, params.Password)
		default:
			err = errICERoleUnknown
		}
	}
	if err == nil && !sped {
		err = agent.AwaitConnect(operationCtx)
	}

	t.lock.Lock()
	if ctxErr := callerCtx.Err(); ctxErr != nil {
		t.lock.Unlock()
		_ = t.Stop()
		t.lock.Lock()

		return ctxErr
	}
	if t.stopped {
		return ice.ErrClosed
	}
	if err != nil {
		if t.ctxCancel != nil {
			t.ctxCancel()
			t.ctxCancel = nil
		}
		if t.dtlsCallbackArmed {
			t.disarmDtlsCallbackLocked()
			agent.SetDtlsFailed()
			agent.SetDtlsCallback(nil)
		}

		return err
	}

	t.conn = iceConn

	config := mux.Config{
		Conn:          t.conn,
		BufferSize:    int(t.gatherer.api.settingEngine.getReceiveMTU()), //nolint:gosec // G115
		LoggerFactory: t.loggerFactory,
	}
	t.mux = mux.NewMux(config)

	return nil
}

func (t *ICETransport) SetDtlsCallback(cb func(packet []byte, rAddr net.Addr)) {
	t.lock.Lock()
	if t.stopped {
		t.lock.Unlock()

		return
	}

	t.dtlsCallback = cb

	dtlsCallbackArmed := false
	if t.gatherer != nil {
		if agent := t.gatherer.getAgent(); agent != nil {
			if t.gatherer.api.settingEngine.enableSped && cb != nil {
				if !t.dtlsCallbackArmed {
					agent.SetDtlsCallback(t.handleDtlsPacket)
				}
				dtlsCallbackArmed = true
			} else {
				agent.SetDtlsCallback(cb)
			}
		}
	}
	t.dtlsCallbackArmed = dtlsCallbackArmed
	t.dtlsCallbackCond.Broadcast()
	t.lock.Unlock()
}

// disarmDtlsCallbackLocked releases the early-packet barrier. It must run before
// physical ICE closure and does not acquire the agent or gatherer lock.
func (t *ICETransport) disarmDtlsCallbackLocked() {
	t.dtlsCallback = nil
	t.dtlsCallbackArmed = false
	if t.dtlsCallbackCond != nil {
		t.dtlsCallbackCond.Broadcast()
	}
}

// CanWrite reports whether the ICE transport can write application data through
// either its selected pair or its best valid pair.
func (t *ICETransport) CanWrite() bool {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return !t.stopped && t.conn != nil && t.conn.CanWrite()
}

func (t *ICETransport) handleDtlsPacket(packet []byte, rAddr net.Addr) {
	t.lock.Lock()
	for t.dtlsCallback == nil && t.dtlsCallbackArmed && !t.stopped {
		t.dtlsCallbackCond.Wait()
	}
	cb := t.dtlsCallback
	t.lock.Unlock()

	if cb != nil {
		cb(packet, rAddr)
	}
}

// restart is not exposed currently because ORTC has users create a whole new ICETransport
// so for now lets keep it private so we don't cause ORTC users to depend on non-standard APIs.
func (t *ICETransport) restart() error {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()

	t.lock.RLock()
	gatherer, stopped := t.gatherer, t.stopped
	t.lock.RUnlock()
	if stopped {
		return errICETransportClosed
	}
	if gatherer == nil {
		return fmt.Errorf("%w: unable to restart ICETransport", errICEAgentNotExist)
	}

	agent := gatherer.getAgent()
	if agent == nil {
		return fmt.Errorf("%w: unable to restart ICETransport", errICEAgentNotExist)
	}

	// Restart and Gather wait for the ICE task loop. That loop can synchronously
	// deliver a SPED packet through handleDtlsPacket, which needs t.lock.
	if err := agent.Restart(
		gatherer.api.settingEngine.candidates.UsernameFragment,
		gatherer.api.settingEngine.candidates.Password,
	); err != nil {
		return err
	}

	t.lock.RLock()
	stopped = t.stopped
	t.lock.RUnlock()
	if stopped {
		return errICETransportClosed
	}

	return gatherer.Gather()
}

// Stop irreversibly stops the ICETransport.
func (t *ICETransport) Stop() error {
	return t.stop(false /* shouldGracefullyClose */)
}

// GracefulStop irreversibly stops the ICETransport. It also waits
// for any goroutines it started to complete. This is only safe to call outside of
// ICETransport callbacks or if in a callback, in its own goroutine.
func (t *ICETransport) GracefulStop() error {
	return t.stop(true /* shouldGracefullyClose */)
}

func (t *ICETransport) stop(shouldGracefullyClose bool) error {
	t.lock.Lock()
	t.stopped = true
	t.setState(ICETransportStateClosed)
	// An early SPED packet may be waiting on the ICE task loop for DTLS setup.
	// Release it before closing the agent, whose Close joins that task loop.
	t.disarmDtlsCallbackLocked()

	if t.ctxCancel != nil {
		t.ctxCancel()
		t.ctxCancel = nil
	}

	// The stopped latch prevents startup from installing a late mux or gatherer.
	mux := t.mux
	gatherer := t.gatherer
	t.lock.Unlock()

	if mux != nil {
		var closeErrs []error
		if shouldGracefullyClose && gatherer != nil {
			// we can't access icegatherer/icetransport.Close via
			// mux's net.Conn Close so we call it earlier here.
			closeErrs = append(closeErrs, gatherer.GracefulClose())
		}
		closeErrs = append(closeErrs, mux.Close())

		return util.FlattenErrs(closeErrs)
	} else if gatherer != nil {
		if shouldGracefullyClose {
			return gatherer.GracefulClose()
		}

		return gatherer.Close()
	}

	return nil
}

// OnSelectedCandidatePairChange sets a handler that is invoked when a new
// ICE candidate pair is selected.
func (t *ICETransport) OnSelectedCandidatePairChange(f func(*ICECandidatePair)) {
	t.onSelectedCandidatePairChangeHandler.Store(f)
}

func (t *ICETransport) onSelectedCandidatePairChange(pair *ICECandidatePair) {
	if handler, ok := t.onSelectedCandidatePairChangeHandler.Load().(func(*ICECandidatePair)); ok {
		handler(pair)
	}
}

// OnConnectionStateChange sets a handler that is fired when the ICE
// connection state changes.
func (t *ICETransport) OnConnectionStateChange(f func(ICETransportState)) {
	t.onConnectionStateChangeHandler.Store(f)
}

func (t *ICETransport) onConnectionStateChange(state ICETransportState) {
	if handler, ok := t.onConnectionStateChangeHandler.Load().(func(ICETransportState)); ok {
		handler(state)
	}
	if handler, ok := t.internalOnConnectionStateChangeHandler.Load().(func(ICETransportState)); ok {
		handler(state)
	}
}

// Role indicates the current role of the ICE transport.
func (t *ICETransport) Role() ICERole {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.role
}

// SetRemoteCandidates sets the sequence of candidates associated with the remote ICETransport.
func (t *ICETransport) SetRemoteCandidates(remoteCandidates []ICECandidate) error {
	t.lock.RLock()
	defer t.lock.RUnlock()

	if err := t.ensureGatherer(); err != nil {
		return err
	}

	agent := t.gatherer.getAgent()
	if agent == nil {
		return fmt.Errorf("%w: unable to set remote candidates", errICEAgentNotExist)
	}

	for _, c := range remoteCandidates {
		i, err := c.ToICE()
		if err != nil {
			return err
		}

		if err = agent.AddRemoteCandidate(i); err != nil {
			return err
		}
	}

	return nil
}

// AddRemoteCandidate adds a candidate associated with the remote ICETransport.
func (t *ICETransport) AddRemoteCandidate(remoteCandidate *ICECandidate) error {
	t.lock.RLock()
	defer t.lock.RUnlock()

	var (
		candidate ice.Candidate
		err       error
	)

	if err = t.ensureGatherer(); err != nil {
		return err
	}

	if remoteCandidate != nil {
		if candidate, err = remoteCandidate.ToICE(); err != nil {
			return err
		}
	}

	agent := t.gatherer.getAgent()
	if agent == nil {
		return fmt.Errorf("%w: unable to add remote candidates", errICEAgentNotExist)
	}

	return agent.AddRemoteCandidate(candidate)
}

// State returns the current ice transport state.
func (t *ICETransport) State() ICETransportState {
	if v, ok := t.state.Load().(ICETransportState); ok {
		return v
	}

	return ICETransportState(0)
}

// GetLocalParameters returns an IceParameters object which provides information
// uniquely identifying the local peer for the duration of the ICE session.
func (t *ICETransport) GetLocalParameters() (ICEParameters, error) {
	if err := t.ensureGatherer(); err != nil {
		return ICEParameters{}, err
	}

	return t.gatherer.GetLocalParameters()
}

// GetRemoteParameters returns an IceParameters object which provides information
// uniquely identifying the remote peer for the duration of the ICE session.
func (t *ICETransport) GetRemoteParameters() (ICEParameters, error) {
	agent := t.remoteCredentialsAgent()
	if agent == nil {
		return ICEParameters{}, fmt.Errorf("%w: unable to get remote parameters", errICEAgentNotExist)
	}

	uFrag, uPwd, err := agent.GetRemoteUserCredentials()
	if err != nil {
		return ICEParameters{}, fmt.Errorf("%w: unable to get remote parameters", err)
	}

	return ICEParameters{
		UsernameFragment: uFrag,
		Password:         uPwd,
	}, nil
}

func (t *ICETransport) setState(i ICETransportState) {
	t.state.Store(i)
}

func (t *ICETransport) newEndpoint(f mux.MatchFunc) *mux.Endpoint {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.mux.NewEndpoint(f)
}

func (t *ICETransport) ensureGatherer() error {
	if t.gatherer == nil {
		return errICEGathererNotStarted
	} else if t.gatherer.getAgent() == nil {
		if err := t.gatherer.createAgent(); err != nil {
			return err
		}
	}

	return nil
}

// Stats reports the current statistics of the ICETransport.
func (t *ICETransport) Stats() TransportStats {
	t.lock.RLock()
	conn := t.conn
	t.lock.RUnlock()

	stats := TransportStats{
		Timestamp: statsTimestampFrom(time.Now()),
		Type:      StatsTypeTransport,
		ID:        "iceTransport",
	}
	if conn != nil {
		stats.BytesSent = conn.BytesSent()
		stats.BytesReceived = conn.BytesReceived()
	}

	return stats
}

func (t *ICETransport) collectStats(collector *statsReportCollector) {
	collector.Collecting()
	stats := t.Stats()
	collector.Collect(stats.ID, stats)
}

func (t *ICETransport) haveRemoteCredentialsChange(newUfrag, newPwd string) bool {
	agent := t.remoteCredentialsAgent()
	if agent == nil {
		return false
	}

	uFrag, uPwd, err := agent.GetRemoteUserCredentials()
	if err != nil {
		return false
	}

	return uFrag != newUfrag || uPwd != newPwd
}

func (t *ICETransport) setRemoteCredentials(newUfrag, newPwd string) error {
	agent := t.remoteCredentialsAgent()
	if agent == nil {
		return fmt.Errorf("%w: unable to SetRemoteCredentials", errICEAgentNotExist)
	}

	return agent.SetRemoteCredentials(newUfrag, newPwd)
}

// Credential operations also wait for the ICE task loop. Take a snapshot so
// neither the gatherer lookup nor those operations hold the SPED callback lock.
func (t *ICETransport) remoteCredentialsAgent() *ice.Agent {
	t.lock.RLock()
	gatherer := t.gatherer
	t.lock.RUnlock()
	if gatherer == nil {
		return nil
	}

	return gatherer.getAgent()
}

// Piggyback forwards a complete DTLS flight to the ICE Agent for STUN embedding.
func (t *ICETransport) Piggyback(datagrams [][]byte, rAddr net.Addr) bool {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.stopped || t.gatherer == nil {
		return false
	}

	agent := t.gatherer.getAgent()
	if agent == nil {
		t.log.Warnf("%w: unable to piggyback DTLS packet", errICEAgentNotExist)

		return false
	}

	return agent.Piggyback(datagrams, rAddr)
}

func (t *ICETransport) ReportDtlsPacket(packet []byte) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.stopped || t.gatherer == nil {
		return
	}

	agent := t.gatherer.getAgent()
	if agent == nil {
		t.log.Warnf("%w: unable to report DTLS packet", errICEAgentNotExist)

		return
	}
	agent.ReportDtlsPacket(packet)
}

// SetDtlsHandshakeComplete records the negotiated role/version in ICE's SPED controller.
func (t *ICETransport) SetDtlsHandshakeComplete(isClient bool, version protocol.Version) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.stopped || t.gatherer == nil {
		return
	}
	if agent := t.gatherer.getAgent(); agent != nil {
		agent.SetDtlsHandshakeComplete(isClient, version)
	}
}

func (t *ICETransport) setDtlsFailed() {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.stopped || t.gatherer == nil {
		return
	}
	if agent := t.gatherer.getAgent(); agent != nil {
		agent.SetDtlsFailed()
	}
}
