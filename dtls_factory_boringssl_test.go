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
