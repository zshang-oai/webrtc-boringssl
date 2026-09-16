// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mux

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
	"github.com/stretchr/testify/require"
)

// Only the test goroutine writes or changes this connection's route state.
type mediaRouteConn struct {
	net.Conn
	unavailable bool
	dropped     int
	forwarded   int
	packetSize  int
}

func (c *mediaRouteConn) Write(packet []byte) (int, error) {
	c.packetSize = len(packet)
	if c.unavailable {
		c.dropped++

		return 0, ice.ErrNoCandidatePairs
	}
	c.forwarded++

	return c.Conn.Write(packet)
}

type mediaReadStream interface {
	io.Reader
	SetReadDeadline(time.Time) error
}

// A no-route media write is packet loss, not a closed SRTP/SRTCP session. Use
// real encryption, mux dispatch and decryption; only the underlying ICE error
// is injected. Lost media is not queued or retransmitted by this policy.
func TestEndpointMediaSurvivesNoCandidatePairs(t *testing.T) {
	const ssrc = 5000
	for _, profile := range []srtp.ProtectionProfile{
		srtp.ProtectionProfileAes128CmHmacSha1_80,
		srtp.ProtectionProfileAeadAes128Gcm,
	} {
		for _, protocol := range []string{"SRTP", "SRTCP"} {
			t.Run(profile.String()+"/"+protocol, func(t *testing.T) {
				a, b := net.Pipe()
				route := &mediaRouteConn{Conn: a}
				newMux := func(conn net.Conn) *Mux {
					m := NewMux(Config{
						Conn: conn, BufferSize: 1500, LoggerFactory: logging.NewDefaultLoggerFactory(),
					})
					t.Cleanup(func() { require.NoError(t, m.Close()) })

					return m
				}
				sender, receiver := newMux(route), newMux(b)
				keyLen, err := profile.KeyLen()
				require.NoError(t, err)
				saltLen, err := profile.SaltLen()
				require.NoError(t, err)
				config := &srtp.Config{
					Profile: profile,
					Keys: srtp.SessionKeys{
						LocalMasterKey: make([]byte, keyLen), LocalMasterSalt: make([]byte, saltLen),
						RemoteMasterKey: make([]byte, keyLen), RemoteMasterSalt: make([]byte, saltLen),
					},
				}

				var writer io.Writer
				var reader mediaReadStream
				var packet func(uint16) []byte
				if protocol == "SRTP" {
					out, sessionErr := srtp.NewSessionSRTP(sender.NewEndpoint(MatchSRTP), config)
					require.NoError(t, sessionErr)
					t.Cleanup(func() { require.NoError(t, out.Close()) })
					in, sessionErr := srtp.NewSessionSRTP(receiver.NewEndpoint(MatchSRTP), config)
					require.NoError(t, sessionErr)
					t.Cleanup(func() { require.NoError(t, in.Close()) })
					writer, err = out.OpenWriteStream()
					require.NoError(t, err)
					reader, err = in.OpenReadStream(ssrc)
					require.NoError(t, err)
					packet = func(sequence uint16) []byte {
						raw, marshalErr := (&rtp.Packet{
							Header:  rtp.Header{Version: 2, PayloadType: 96, SSRC: ssrc, SequenceNumber: sequence},
							Payload: []byte("media payload"),
						}).Marshal()
						require.NoError(t, marshalErr)

						return raw
					}
				} else {
					out, sessionErr := srtp.NewSessionSRTCP(sender.NewEndpoint(MatchSRTCP), config)
					require.NoError(t, sessionErr)
					t.Cleanup(func() { require.NoError(t, out.Close()) })
					in, sessionErr := srtp.NewSessionSRTCP(receiver.NewEndpoint(MatchSRTCP), config)
					require.NoError(t, sessionErr)
					t.Cleanup(func() { require.NoError(t, in.Close()) })
					writer, err = out.OpenWriteStream()
					require.NoError(t, err)
					reader, err = in.OpenReadStream(ssrc)
					require.NoError(t, err)
					packet = func(sequence uint16) []byte {
						raw, marshalErr := (&rtcp.PictureLossIndication{
							SenderSSRC: uint32(sequence), MediaSSRC: ssrc,
						}).Marshal()
						require.NoError(t, marshalErr)

						return raw
					}
				}

				write := func(raw []byte) {
					n, writeErr := writer.Write(raw)
					require.NoError(t, writeErr)
					// SRTP's write streams return the encrypted datagram's byte count.
					require.Equal(t, route.packetSize, n)
				}
				read := func(want []byte) {
					require.NoError(t, reader.SetReadDeadline(time.Now().Add(2*time.Second)))
					buf := make([]byte, 1500)
					n, readErr := reader.Read(buf)
					require.NoError(t, readErr)
					require.Equal(t, want, buf[:n])
				}

				write(packet(1))
				read(packet(1))
				require.Equal(t, 1, route.forwarded)

				route.unavailable = true
				write(packet(2))
				require.Equal(t, 1, route.dropped, "the underlying transport returned no candidate pairs")
				require.Equal(t, 1, route.forwarded, "the lost packet never reached the pipe")

				route.unavailable = false
				write(packet(3))
				read(packet(3)) // No queued replay of packet 2; the existing sessions still work.
				require.Equal(t, 2, route.forwarded)
			})
		}
	}
}
