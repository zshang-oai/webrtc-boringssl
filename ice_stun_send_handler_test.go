// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"errors"
	"hash/crc32"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5/vnet"
	"github.com/stretchr/testify/require"
)

// Exercise the SettingEngine -> gatherer -> ICE response path, not just field
// forwarding. Public mapped addresses are deliberately outside the test route.
//
//nolint:cyclop // Cover each handler state with the same authenticated wire exchange.
func TestICEGathererSTUNSendHandlerOnWire(t *testing.T) {
	for _, mode := range []string{"default", "rewrite-ipv4", "rewrite-ipv6", "cleared", "error"} {
		t.Run(mode, func(t *testing.T) {
			type observation struct {
				requestID     [stun.TransactionIDSize]byte
				local, remote string
				responseType  stun.MessageType
				attributes    []stun.AttrType
			}
			observed := make(chan observation, 1)
			mappedIP, mappedPort := net.ParseIP("203.0.113.10"), 45678
			if mode == "rewrite-ipv6" {
				mappedIP = net.ParseIP("2001:db8::10")
			}
			handler := func(outbound, inbound *stun.Message, local, remote ice.Candidate) error {
				attrs := make([]stun.AttrType, len(outbound.Attributes))
				for i, attr := range outbound.Attributes {
					attrs[i] = attr.Type
				}
				select {
				case observed <- observation{inbound.TransactionID, net.JoinHostPort(local.Address(), strconv.Itoa(local.Port())),
					net.JoinHostPort(remote.Address(), strconv.Itoa(remote.Port())), outbound.Type, attrs}:
				default:
					return errors.New("unexpected extra response")
				}
				if mode == "error" {
					return errors.New("test suppresses response")
				}
				// Rebuild rather than append a duplicate XOR-MAPPED-ADDRESS. ICE
				// adds SPED and integrity attributes after this callback returns.
				return outbound.Build(inbound, stun.BindingSuccess, &stun.XORMappedAddress{IP: mappedIP, Port: mappedPort})
			}
			settings := SettingEngine{}
			if mode != "default" {
				settings.SetICESTUNSendHandler(handler)
			}
			if mode == "cleared" {
				settings.SetICESTUNSendHandler(nil)
			}
			agent, client, serverAddr := newSTUNSendHandlerWirePeer(t, settings)
			agent.SetDtlsCallback(func([]byte, net.Addr) {})
			outgoing, incoming := spedTestRecord("server flight"), spedTestRecord("client flight")
			require.True(t, agent.Piggyback([][]byte{outgoing}, nil))
			agent.ReportDtlsPacket(incoming)
			ufrag, password, err := agent.GetLocalUserCredentials()
			require.NoError(t, err)
			_, err = agent.StartAccept("remote-ufrag", "remote-password-long-enough")
			require.NoError(t, err)
			request, err := stun.Build(stun.BindingRequest, stun.TransactionID,
				stun.NewUsername(ufrag+":remote-ufrag"), ice.AttrControlling(1), ice.PriorityAttr(1234),
				ice.DtlsInStunAttribute(incoming), ice.DtlsInStunAckAttribute{},
				stun.NewShortTermIntegrity(password), stun.Fingerprint)
			require.NoError(t, err)
			_, err = client.WriteTo(request.Raw, serverAddr)
			require.NoError(t, err)
			require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
			if mode == "error" {
				require.NoError(t, client.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
			}
			packet := make([]byte, 1500)
			n, source, err := client.ReadFrom(packet)
			if mode == "error" {
				var timeout net.Error
				require.ErrorAs(t, err, &timeout)
				require.True(t, timeout.Timeout(), "an error from the callback must suppress the response")
			} else {
				require.NoError(t, err)
				require.Equal(t, serverAddr.String(), source.String(), "physical response route must remain unchanged")
				response := &stun.Message{Raw: packet[:n]}
				require.NoError(t, response.Decode())
				require.Equal(t, request.TransactionID, response.TransactionID)
				require.Equal(t, stun.BindingSuccess, response.Type)
				require.NoError(t, stun.MessageIntegrity([]byte(password)).Check(response))
				require.NoError(t, stun.Fingerprint.Check(response))
				var mapped stun.XORMappedAddress
				require.NoError(t, mapped.GetFrom(response))
				if mode == "default" || mode == "cleared" {
					physical := client.LocalAddr().(*net.UDPAddr)
					mappedIP, mappedPort = physical.IP, physical.Port
				}
				require.True(t, mapped.IP.Equal(mappedIP))
				require.Equal(t, mappedPort, mapped.Port)
				var data ice.DtlsInStunAttribute
				require.NoError(t, data.GetFrom(response))
				require.Equal(t, outgoing, []byte(data))
				var acks ice.DtlsInStunAckAttribute
				require.NoError(t, acks.GetFrom(response))
				require.Equal(t, ice.DtlsInStunAckAttribute{crc32.ChecksumIEEE(incoming)}, acks)
				types := make([]stun.AttrType, len(response.Attributes))
				for i, attr := range response.Attributes {
					types[i] = attr.Type
				}
				require.Equal(t, []stun.AttrType{stun.AttrXORMappedAddress, stun.AttrDtlsInStunAck,
					stun.AttrDtlsInStun, stun.AttrMessageIntegrity, stun.AttrFingerprint}, types)
			}
			if mode == "default" || mode == "cleared" {
				require.Empty(t, observed)
			} else {
				select {
				case got := <-observed:
					require.Equal(t, request.TransactionID, got.requestID)
					require.Equal(t, serverAddr.String(), got.local)
					require.Equal(t, client.LocalAddr().String(), got.remote)
					require.Equal(t, stun.BindingSuccess, got.responseType)
					require.Equal(t, []stun.AttrType{stun.AttrXORMappedAddress}, got.attributes)
				default:
					require.FailNow(t, "gatherer did not forward the STUN send handler")
				}
			}
			remotes, err := agent.GetRemoteCandidates()
			require.NoError(t, err)
			require.Len(t, remotes, 1)
			remoteAddr := net.JoinHostPort(remotes[0].Address(), strconv.Itoa(remotes[0].Port()))
			require.Equal(t, client.LocalAddr().String(), remoteAddr)
		})
	}
}

func newSTUNSendHandlerWirePeer(t *testing.T, settings SettingEngine) (*ice.Agent, net.PacketConn, net.Addr) {
	t.Helper()
	wan, err := vnet.NewRouter(&vnet.RouterConfig{CIDR: "0.0.0.0/0", LoggerFactory: logging.NewDefaultLoggerFactory()})
	require.NoError(t, err)
	clientNet, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{"192.168.0.1"}})
	require.NoError(t, err)
	serverNet, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{"192.168.0.2"}})
	require.NoError(t, err)
	require.NoError(t, wan.AddNet(clientNet))
	require.NoError(t, wan.AddNet(serverNet))
	require.NoError(t, wan.Start())
	t.Cleanup(func() { require.NoError(t, wan.Stop()) })
	client, err := clientNet.ListenPacket("udp4", "192.168.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	settings.SetNet(serverNet)
	settings.SetLite(true)
	settings.SetNetworkTypes([]NetworkType{NetworkTypeUDP4})
	settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	gatherer, err := NewAPI(WithSettingEngine(settings)).NewICEGatherer(ICEGatherOptions{})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, gatherer.Close()) })
	gathered := make(chan struct{})
	gatherer.OnLocalCandidate(func(candidate *ICECandidate) {
		if candidate == nil {
			close(gathered)
		}
	})
	require.NoError(t, gatherer.Gather())
	select {
	case <-gathered:
	case <-time.After(time.Second):
		require.FailNow(t, "gathering did not finish")
	}
	candidates, err := gatherer.GetLocalCandidates()
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	return gatherer.getAgent(), client, &net.UDPAddr{IP: net.ParseIP(candidates[0].Address), Port: int(candidates[0].Port)}
}
