// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/pion/sctp"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/require"
)

func newSCTPMessageAckPair(t *testing.T, bufferSize int, boringSSL bool) (
	*testORTCStack, *testORTCStack, *DataChannel, <-chan DataChannelMessage,
) {
	t.Helper()
	t.Cleanup(test.CheckRoutines(t))
	stackA, stackB, err := newORTCPair()
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, stackA.close())
		require.NoError(t, stackB.close())
	})
	require.NoError(t, stackA.api.settingEngine.SetSCTPMessageAckBufferSize(bufferSize))
	for _, stack := range []*testORTCStack{stackA, stackB} {
		stack.api.settingEngine.SetSCTPMaxMessageSize(1 << 20)
	}
	if boringSSL {
		stackA.api.settingEngine.SetDTLSFactory(NewBoringSSLFactory())
		stackA.api.settingEngine.SetDTLSInsecureSkipHelloVerify(true)
	}
	require.Nil(t, stackA.sctp.MessageAcks(), "SCTP has not started")
	received := make(chan DataChannelMessage, 1)
	stackB.sctp.OnDataChannel(func(d *DataChannel) {
		d.OnMessage(func(message DataChannelMessage) { received <- message })
	})
	require.NoError(t, signalORTCPair(stackA, stackB))
	stackA.sctp.association().SetMaxMessageSize(1 << 20)
	stackB.sctp.association().SetMaxMessageSize(1 << 20)
	require.Nil(t, stackB.sctp.MessageAcks(), "instrumentation defaults to disabled")
	id := uint16(1)
	sender, err := stackA.api.NewDataChannel(stackA.sctp, &DataChannelParameters{
		Label: "ack-test", ID: &id, Ordered: true,
	})
	require.NoError(t, err)

	return stackA, stackB, sender, received
}

func TestSCTPMessageAckInstrumentation(t *testing.T) {
	for _, boringSSL := range []bool{false, true} {
		name := "Pion"
		if boringSSL {
			name = "BoringSSL"
		}
		t.Run(name, func(t *testing.T) {
			stackA, _, sender, received := newSCTPMessageAckPair(t, 8, boringSSL)
			acks := stackA.sctp.MessageAcks()
			require.NotNil(t, acks)
			messages := []DataChannelMessage{
				{Data: []byte("text"), IsString: true},
				{IsString: true},
				{},
				{Data: bytes.Repeat([]byte{73}, 256<<10)},
				{Data: bytes.Repeat([]byte{74}, 384<<10), IsString: true},
				{Data: bytes.Repeat([]byte{75}, 512<<10)},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for i, message := range messages {
				beforeSend := time.Now()
				if message.IsString {
					require.NoError(t, sender.SendText(string(message.Data)))
				} else {
					require.NoError(t, sender.Send(message.Data))
				}
				select {
				case actual := <-received:
					require.Equal(t, message.IsString, actual.IsString)
					require.True(t, bytes.Equal(message.Data, actual.Data))
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				select {
				case ack := <-acks:
					require.NoError(t, ack.Err)
					require.EqualValues(t, i+1, ack.MessageID, "DCEP does not produce application-message events")
					require.Equal(t, *sender.ID(), ack.StreamIdentifier)
					require.EqualValues(t, max(1, len(message.Data)), ack.PayloadSize)
					expectedType := sctp.PayloadTypeWebRTCBinary
					if message.IsString {
						expectedType = sctp.PayloadTypeWebRTCString
					}
					if len(message.Data) == 0 {
						expectedType = sctp.PayloadTypeWebRTCBinaryEmpty
						if message.IsString {
							expectedType = sctp.PayloadTypeWebRTCStringEmpty
						}
					}
					require.Equal(t, expectedType, ack.PayloadType)
					require.False(t, ack.WriteStartedAt.Before(beforeSend))
					require.False(t, ack.QueuedAt.Before(ack.WriteStartedAt))
					require.False(t, ack.FirstTransmissionAt.Before(ack.QueuedAt))
					require.False(t, ack.FirstAcknowledgedAt.Before(ack.FirstTransmissionAt))
					require.False(t, ack.CumulativelyAcknowledgedAt.Before(ack.FirstAcknowledgedAt))
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			require.Zero(t, stackA.sctp.MessageAckEventsDropped())
			require.NoError(t, stackA.sctp.Stop())
			require.Equal(t, acks, stackA.sctp.MessageAcks())
			_, open := <-acks
			require.False(t, open)
		})
	}
}

func TestSCTPMessageAckOverflowPreservesSendsAndFinalCount(t *testing.T) {
	stackA, _, sender, received := newSCTPMessageAckPair(t, 1, false)
	for range 3 {
		require.NoError(t, sender.SendText("ordinary send"))
		select {
		case message := <-received:
			require.Equal(t, "ordinary send", string(message.Data))
		case <-time.After(5 * time.Second):
			t.Fatal("message was not delivered")
		}
		require.Eventually(t, func() bool { return sender.BufferedAmount() == 0 }, 5*time.Second, time.Millisecond)
	}
	require.EqualValues(t, 2, stackA.sctp.MessageAckEventsDropped())
	acks := stackA.sctp.MessageAcks()
	require.NoError(t, stackA.sctp.Stop())
	require.Equal(t, acks, stackA.sctp.MessageAcks())
	require.EqualValues(t, 2, stackA.sctp.MessageAckEventsDropped())
	ack, open := <-acks
	require.True(t, open)
	require.EqualValues(t, 1, ack.MessageID)
	_, open = <-acks
	require.False(t, open)
}

func TestSCTPMessageAckConfiguration(t *testing.T) {
	var settingEngine SettingEngine
	require.ErrorIs(t, settingEngine.SetSCTPMessageAckBufferSize(-1), errSCTPMessageAckBufferSize)
	require.NoError(t, settingEngine.SetSCTPMessageAckBufferSize(1))
	require.NoError(t, settingEngine.SetSCTPMessageAckBufferSize(0))
	require.Zero(t, settingEngine.sctp.messageAckBufferSize)
}
