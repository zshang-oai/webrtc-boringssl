// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build boringssl && !js
// +build boringssl,!js

package webrtc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBoringSSLFactory_InteropWithPionDTLS12(t *testing.T) {
	clientPacketConn := newLocalUDPConn(t)
	serverPacketConn := newLocalUDPConn(t)

	serverDone := make(chan error, 1)
	go func() {
		server, err := dtls.Server(serverPacketConn, clientPacketConn.LocalAddr(), newInteropDTLSConfig(t))
		if err != nil {
			serverDone <- err
			return
		}
		defer func() {
			_ = server.Close()
		}()

		serverDone <- runInteropServer(&pionDTLSConn{Conn: server})
	}()

	client, err := NewBoringSSLFactory().Client(packetConnOnly{clientPacketConn}, serverPacketConn.LocalAddr(), newInteropDTLSConfig(t))
	require.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	assert.Equal(t, "pong", runInteropClient(t, client))
	require.NoError(t, <-serverDone)
}

func TestBoringSSLFactory_InteropDTLS13(t *testing.T) {
	clientPacketConn := newLocalUDPConn(t)
	serverPacketConn := newLocalUDPConn(t)

	serverConfig := newInteropDTLSConfig(t)
	serverConfig.InsecureSkipVerifyHello = true

	serverReady := make(chan *boringSSLConn, 1)
	serverDone := make(chan error, 1)
	go func() {
		server, err := NewBoringSSLFactory().Server(packetConnOnly{serverPacketConn}, clientPacketConn.LocalAddr(), serverConfig)
		if err != nil {
			serverDone <- err
			return
		}
		serverReady <- server.(*boringSSLConn)

		serverDone <- runInteropServer(server)
	}()

	client, err := NewBoringSSLFactory().Client(packetConnOnly{clientPacketConn}, serverPacketConn.LocalAddr(), newInteropDTLSConfig(t))
	require.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	assert.Equal(t, "pong", runInteropClient(t, client))
	require.NoError(t, <-serverDone)

	clientConn := client.(*boringSSLConn)
	serverConn := <-serverReady
	defer func() {
		_ = serverConn.Close()
	}()
	assert.Equal(t, 0xfefc, clientConn.negotiatedVersion())
	assert.Equal(t, 0xfefc, serverConn.negotiatedVersion())
}

func TestBoringSSLFactory_ReadDoesNotBlockConcurrentWrite(t *testing.T) {
	clientPacketConn := newLocalUDPConn(t)
	serverPacketConn := &readSignalPacketConn{
		PacketConn: newLocalUDPConn(t),
	}

	serverConfig := newInteropDTLSConfig(t)
	serverConfig.InsecureSkipVerifyHello = true

	serverReady := make(chan *boringSSLConn, 1)
	serverHandshakeDone := make(chan error, 1)
	go func() {
		server, err := NewBoringSSLFactory().Server(packetConnOnly{serverPacketConn}, clientPacketConn.LocalAddr(), serverConfig)
		if err != nil {
			serverHandshakeDone <- err
			return
		}

		serverConn := server.(*boringSSLConn)
		serverReady <- serverConn

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		serverHandshakeDone <- serverConn.HandshakeContext(ctx)
	}()

	client, err := NewBoringSSLFactory().Client(
		packetConnOnly{clientPacketConn},
		serverPacketConn.LocalAddr(),
		newInteropDTLSConfig(t),
	)
	require.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	var server *boringSSLConn
	select {
	case server = <-serverReady:
	case err := <-serverHandshakeDone:
		require.NoError(t, err)
		require.FailNow(t, "server handshake completed before server setup was published")
	case <-time.After(2 * time.Second):
		require.FailNow(t, "timed out waiting for BoringSSL server setup")
	}
	defer func() {
		_ = server.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, client.HandshakeContext(ctx))
	require.NoError(t, <-serverHandshakeDone)

	readStarted := serverPacketConn.signalNextRead()
	serverReadDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := server.Read(buf)
		serverReadDone <- err
	}()

	select {
	case <-readStarted:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "timed out waiting for server read to reach the underlying connection")
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := server.Write([]byte("pong"))
		writeDone <- err
	}()

	select {
	case err := <-writeDone:
		require.NoError(t, err)
	case <-time.After(500 * time.Millisecond):
		require.FailNow(t, "server write blocked behind an idle server read")
	}

	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 4)
	n, err := client.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "pong", string(buf[:n]))

	require.NoError(t, server.SetReadDeadline(time.Now()))
	select {
	case <-serverReadDone:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "timed out waiting for server read to unblock")
	}
}

func TestBoringSSLFactory_DataChannelCanSendWhileReadLoopIdle(t *testing.T) {
	answerSettingEngine := SettingEngine{}
	answerSettingEngine.SetDTLSFactory(NewBoringSSLFactory())
	answerSettingEngine.SetDTLSInsecureSkipHelloVerify(true)

	offer, err := NewPeerConnection(Configuration{})
	require.NoError(t, err)
	answer, err := NewAPI(WithSettingEngine(answerSettingEngine)).NewPeerConnection(Configuration{})
	require.NoError(t, err)
	defer closePairNow(t, offer, answer)

	dataChannelID := uint16(0)
	negotiated := true
	dataChannelOptions := &DataChannelInit{
		ID:         &dataChannelID,
		Negotiated: &negotiated,
	}

	offerDataChannel, err := offer.CreateDataChannel("control", dataChannelOptions)
	require.NoError(t, err)
	answerDataChannel, err := answer.CreateDataChannel("control", dataChannelOptions)
	require.NoError(t, err)

	offerOpened := make(chan struct{})
	answerOpened := make(chan struct{})
	receivedMessage := make(chan string, 1)
	offerDataChannel.OnOpen(func() {
		close(offerOpened)
	})
	answerDataChannel.OnOpen(func() {
		close(answerOpened)
	})
	offerDataChannel.OnMessage(func(message DataChannelMessage) {
		receivedMessage <- string(message.Data)
	})

	require.NoError(t, signalPairWithOptions(offer, answer, withDisableInitialDataChannel(true)))

	select {
	case <-offerOpened:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "timed out waiting for offer data channel to open")
	}
	select {
	case <-answerOpened:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "timed out waiting for answer data channel to open")
	}

	sendDone := make(chan error, 1)
	go func() {
		sendDone <- answerDataChannel.SendText("server-state-update")
	}()

	select {
	case err := <-sendDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		require.FailNow(t, "answer data channel send blocked behind its SCTP read loop")
	}

	select {
	case message := <-receivedMessage:
		assert.Equal(t, "server-state-update", message)
	case <-time.After(2 * time.Second):
		require.FailNow(t, "timed out waiting for offer data channel message")
	}
}

func TestBoringSSLFactory_SpedFallsBackWithNonSpedPeer(t *testing.T) {
	answerSettingEngine := SettingEngine{}
	answerSettingEngine.SetDTLSFactory(NewBoringSSLFactory())
	answerSettingEngine.SetDTLSInsecureSkipHelloVerify(true)
	answerSettingEngine.EnableSped(true)

	offer, err := NewPeerConnection(Configuration{})
	require.NoError(t, err)
	answer, err := NewAPI(WithSettingEngine(answerSettingEngine)).NewPeerConnection(Configuration{})
	require.NoError(t, err)
	defer closePairNow(t, offer, answer)

	dataChannelID := uint16(0)
	negotiated := true
	dataChannelOptions := &DataChannelInit{
		ID:         &dataChannelID,
		Negotiated: &negotiated,
	}

	offerDataChannel, err := offer.CreateDataChannel("control", dataChannelOptions)
	require.NoError(t, err)
	answerDataChannel, err := answer.CreateDataChannel("control", dataChannelOptions)
	require.NoError(t, err)

	offerOpened := make(chan struct{})
	answerOpened := make(chan struct{})
	receivedMessage := make(chan string, 1)
	offerDataChannel.OnOpen(func() {
		close(offerOpened)
	})
	answerDataChannel.OnOpen(func() {
		close(answerOpened)
	})
	offerDataChannel.OnMessage(func(message DataChannelMessage) {
		receivedMessage <- string(message.Data)
	})

	require.NoError(t, signalPairWithOptions(offer, answer, withDisableInitialDataChannel(true)))

	select {
	case <-offerOpened:
	case <-time.After(5 * time.Second):
		t.Log(connectionDebugState(offer, answer))
		require.FailNow(t, "timed out waiting for offer data channel to open")
	}
	select {
	case <-answerOpened:
	case <-time.After(5 * time.Second):
		t.Log(connectionDebugState(offer, answer))
		require.FailNow(t, "timed out waiting for answer data channel to open")
	}

	require.NoError(t, answerDataChannel.SendText("sped-fallback-ready"))

	select {
	case message := <-receivedMessage:
		assert.Equal(t, "sped-fallback-ready", message)
	case <-time.After(2 * time.Second):
		t.Log(connectionDebugState(offer, answer))
		require.FailNow(t, "timed out waiting for fallback data channel message")
	}
}

func connectionDebugState(offer, answer *PeerConnection) string {
	return fmt.Sprintf(
		"offer(pc=%s ice=%s dtls=%s) answer(pc=%s ice=%s dtls=%s)",
		offer.ConnectionState(),
		offer.ICEConnectionState(),
		offer.dtlsTransport.State(),
		answer.ConnectionState(),
		answer.ICEConnectionState(),
		answer.dtlsTransport.State(),
	)
}

func TestPacketConnAsConn_UnconnectedUDPConnUsesPacketConnStream(t *testing.T) {
	conn := newLocalUDPConn(t)
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478}

	wrapped := packetConnAsConn(conn, remote)
	stream, ok := wrapped.(*packetConnStream)
	require.True(t, ok)
	assert.Equal(t, remote, stream.RemoteAddr())
}

func newLocalUDPConn(t *testing.T) *net.UDPConn {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	return conn
}

type packetConnOnly struct {
	net.PacketConn
}

type readSignalPacketConn struct {
	net.PacketConn
	mu          sync.Mutex
	readStarted chan struct{}
}

func (c *readSignalPacketConn) signalNextRead() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()

	readStarted := make(chan struct{})
	c.readStarted = readStarted

	return readStarted
}

func (c *readSignalPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	readStarted := c.readStarted
	if readStarted != nil {
		close(readStarted)
		c.readStarted = nil
	}
	c.mu.Unlock()

	return c.PacketConn.ReadFrom(p)
}

func newInteropDTLSConfig(t *testing.T) *dtls.Config {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert, err := GenerateCertificate(key)
	require.NoError(t, err)

	return &dtls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.x509Cert.Raw},
			PrivateKey:  key,
		}},
		SRTPProtectionProfiles: defaultSrtpProtectionProfiles(),
		ClientAuth:             dtls.RequireAnyClientCert,
		InsecureSkipVerify:     true,
	}
}

func runInteropServer(conn DTLSConn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.HandshakeContext(ctx); err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}

	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != "ping" {
		return fmt.Errorf("unexpected message: %q", string(buf[:n]))
	}

	_, err = conn.Write([]byte("pong"))
	return err
}

func runInteropClient(t *testing.T, conn DTLSConn) string {
	t.Helper()

	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := conn.Write([]byte("ping"))
	require.NoError(t, err)

	profile, ok := conn.SelectedSRTPProtectionProfile()
	require.True(t, ok)
	assert.Contains(t, defaultSrtpProtectionProfiles(), profile)

	exporter, ok := conn.KeyingMaterialExporter()
	require.True(t, ok)
	keyingMaterial, err := exporter.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, 32)
	require.NoError(t, err)
	assert.Len(t, keyingMaterial, 32)

	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	require.NoError(t, err)

	return string(buf[:n])
}
