// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package webrtc

import (
	"context"
	"net"

	"github.com/pion/dtls/v3"
	"github.com/pion/srtp/v3"
)

// DTLSConn is the minimal surface required by the WebRTC stack.
type DTLSConn interface {
	net.Conn

	Handshake() error
	HandshakeContext(ctx context.Context) error
	KeyingMaterialExporter() (srtp.KeyingMaterialExporter, bool)
	SelectedSRTPProtectionProfile() (dtls.SRTPProtectionProfile, bool)
}

// DTLSFactory creates DTLS connections for clients and servers.
type DTLSFactory interface {
	Client(conn net.PacketConn, addr net.Addr, cfg *dtls.Config) (DTLSConn, error)
	Server(conn net.PacketConn, addr net.Addr, cfg *dtls.Config) (DTLSConn, error)
}

var defaultDTLSFactory DTLSFactory = pionDTLSFactory{}

func getDTLSFactory(engine *SettingEngine) DTLSFactory {
	if engine != nil && engine.dtls.factory != nil {
		return engine.dtls.factory
	}

	return defaultDTLSFactory
}

type pionDTLSFactory struct{}

func (pionDTLSFactory) Client(conn net.PacketConn, addr net.Addr, cfg *dtls.Config) (DTLSConn, error) {
	c, err := dtls.Client(conn, addr, cfg)
	if err != nil {
		return nil, err
	}

	return &pionDTLSConn{Conn: c}, nil
}

func (pionDTLSFactory) Server(conn net.PacketConn, addr net.Addr, cfg *dtls.Config) (DTLSConn, error) {
	c, err := dtls.Server(conn, addr, cfg)
	if err != nil {
		return nil, err
	}

	return &pionDTLSConn{Conn: c}, nil
}

type pionDTLSConn struct {
	*dtls.Conn
}

func (c *pionDTLSConn) KeyingMaterialExporter() (srtp.KeyingMaterialExporter, bool) {
	if _, ok := c.Conn.ConnectionState(); !ok {
		return nil, false
	}

	return c, true
}

func (c *pionDTLSConn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	state, ok := c.Conn.ConnectionState()
	if !ok {
		return nil, errDTLSConnectionStateUnavailable
	}

	return state.ExportKeyingMaterial(label, context, length)
}
