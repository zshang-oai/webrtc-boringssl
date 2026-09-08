// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"errors"

	"github.com/pion/sctp"
)

var errSCTPMessageAckBufferSize = errors.New("SCTP message acknowledgment buffer size must be nonnegative")

// SCTPMessageAck describes transport observations of one reliable SCTP write.
// WriteStartedAt is the entry to SCTP WriteSCTP, after WebRTC and datachannel
// payload conversion. ACK timestamps include receiver ACK delay and do not
// establish remote application processing. MessageID identifies association-local
// enqueue order, not an application message ID; completion order can differ.
// PayloadSize counts SCTP bytes, including the one-byte empty-message encoding.
type SCTPMessageAck = sctp.MessageAck

// MessageAcks returns the optional transport instrumentation stream. It is nil
// before SCTP starts or when tracking is disabled. Enable it before connection
// creation with SettingEngine.SetSCTPMessageAckBufferSize. The owned channel
// closes when SCTP tracking terminates and remains available after Stop so the
// consumer can drain final events. No DataChannel API or wire changes are needed.
func (r *SCTPTransport) MessageAcks() <-chan SCTPMessageAck {
	r.lock.RLock()
	defer r.lock.RUnlock()

	return r.messageAckEvents
}

// MessageAckEventsDropped reports records dropped because the bounded event
// buffer was full, including terminal failure records. It preserves the final
// count after Stop; a nonzero value means the event stream has incomplete coverage.
func (r *SCTPTransport) MessageAckEventsDropped() uint64 {
	r.lock.RLock()
	defer r.lock.RUnlock()
	if r.sctpAssociation != nil {
		return r.sctpAssociation.MessageAckEventsDropped()
	}

	return r.messageAckEventsDropped
}
