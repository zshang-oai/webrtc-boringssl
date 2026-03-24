// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build boringssl && !js
// +build boringssl,!js

package webrtc

/*
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <stdlib.h>

extern int go_boringssl_write_callback(void* ctx, char* buf, int len);
extern void go_boringssl_flush_callback(void* ctx);
extern int go_boringssl_query_mtu_callback(void* ctx);

static int stream_write(BIO* b, const char* in, int inl);
static long stream_ctrl(BIO* b, int cmd, long num, void* ptr);
static int stream_new(BIO* b);
static int stream_free(BIO* b);
static int verify_callback_allow_all(int preverify_ok, X509_STORE_CTX* x509_ctx);
static void webrtc_ssl_ctx_set_verify(SSL_CTX* ctx, int mode);
static void init_stream_method(void);
static BIO_METHOD* bio_stream_method = NULL;

static void init_stream_method(void) {
  bio_stream_method = BIO_meth_new(BIO_TYPE_BIO, "webrtc_boringssl_stream");
  if (bio_stream_method == NULL) {
    return;
  }
  BIO_meth_set_write(bio_stream_method, stream_write);
  BIO_meth_set_ctrl(bio_stream_method, stream_ctrl);
  BIO_meth_set_create(bio_stream_method, stream_new);
  BIO_meth_set_destroy(bio_stream_method, stream_free);
}

static BIO* BIO_new_stream() {
  if (bio_stream_method == NULL) {
    return NULL;
  }
  BIO* ret = BIO_new(bio_stream_method);
  if (ret == NULL) {
    return NULL;
  }
  return ret;
}

static int stream_new(BIO* b) {
  BIO_set_shutdown(b, 0);
  BIO_set_init(b, 1);
  BIO_set_data(b, NULL);
  return 1;
}

static int stream_free(BIO* b) {
  if (b == NULL) {
    return 0;
  }
  return 1;
}

static int verify_callback_allow_all(int preverify_ok, X509_STORE_CTX* x509_ctx) {
  (void)preverify_ok;
  (void)x509_ctx;
  return 1;
}

static void webrtc_ssl_ctx_set_verify(SSL_CTX* ctx, int mode) {
  SSL_CTX_set_verify(ctx, mode, verify_callback_allow_all);
}

static int stream_write(BIO* b, const char* in, int inl) {
  if (!in) {
    return -1;
  }
  return go_boringssl_write_callback(BIO_get_data(b), (char*)in, inl);
}

static long stream_ctrl(BIO* b, int cmd, long num, void* ptr) {
  (void)num;
  (void)ptr;
  switch (cmd) {
  case BIO_CTRL_RESET:
    return 0;
  case BIO_CTRL_EOF:
    return 0;
  case BIO_CTRL_WPENDING:
  case BIO_CTRL_PENDING:
    return 0;
  case BIO_CTRL_FLUSH:
    go_boringssl_flush_callback(BIO_get_data(b));
    return 1;
  case BIO_CTRL_DGRAM_QUERY_MTU:
    return go_boringssl_query_mtu_callback(BIO_get_data(b));
  default:
    return 0;
  }
}

static int webrtc_ssl_get_selected_srtp_profile(SSL* ssl, unsigned long* out_id) {
  const SRTP_PROTECTION_PROFILE* profile = SSL_get_selected_srtp_profile(ssl);
  if (profile == NULL) {
    return 0;
  }
  *out_id = profile->id;
  return 1;
}

static int webrtc_ssl_get_peer_cert_der(SSL* ssl, uint8_t** out, size_t* out_len) {
  X509* cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL) {
    return 0;
  }
  int len = i2d_X509(cert, NULL);
  if (len <= 0) {
    X509_free(cert);
    return 0;
  }
  uint8_t* buf = OPENSSL_malloc((size_t)len);
  if (buf == NULL) {
    X509_free(cert);
    return 0;
  }
  uint8_t* p = buf;
  if (i2d_X509(cert, &p) != len) {
    OPENSSL_free(buf);
    X509_free(cert);
    return 0;
  }
  X509_free(cert);
  *out = buf;
  *out_len = (size_t)len;
  return 1;
}

static void webrtc_ssl_free(void* p) {
  OPENSSL_free(p);
}
*/
import "C"

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/cgo"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/pion/dtls/v3"
	dtlsElliptic "github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/srtp/v3"
)

// NewBoringSSLFactory returns a DTLSFactory backed by BoringSSL.
//
// Note: set CGO_CFLAGS and CGO_LDFLAGS to point at your BoringSSL build.
func NewBoringSSLFactory() DTLSFactory {
	return &boringSSLFactory{}
}

type boringSSLFactory struct{}

func (f *boringSSLFactory) Client(conn net.PacketConn, addr net.Addr, cfg *dtls.Config) (DTLSConn, error) {
	return newBoringSSLConn(packetConnAsConn(conn, addr), cfg, true)
}

func (f *boringSSLFactory) Server(conn net.PacketConn, addr net.Addr, cfg *dtls.Config) (DTLSConn, error) {
	return newBoringSSLConn(packetConnAsConn(conn, addr), cfg, false)
}

type boringSSLConn struct {
	net.Conn
	ssl                    *C.SSL
	ctx                    *C.SSL_CTX
	readBio                *C.BIO     // Memory BIO that receives inbound DTLS packets before SSL reads them.
	handle                 cgo.Handle // Stable pointer-sized token used by C BIO callbacks to get back to this Go object.
	handlePtr              unsafe.Pointer
	closeOnce              sync.Once
	mu                     sync.Mutex
	writeMu                sync.Mutex
	lastWriteErr           error // Captures Conn.Write failures from the BIO callback so SSL_* callers can return them.
	readMu                 sync.Mutex
	deadlineMu             sync.Mutex
	verify                 func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	profile                dtls.SRTPProtectionProfile
	mtu                    int
	closed                 bool
	readDeadline           time.Time
	writeDeadline          time.Time
	activeReadDeadlineKind readDeadlineKind // Which user operation currently owns the underlying Conn.Read deadline.
	activeReadOpDeadline   time.Time        // Read or write deadline for the operation currently blocked on network input.
	internalReadDeadline   time.Time        // Handshake/context/DTLS timer deadline merged into the active Conn.Read deadline.
	readDeadlineSeq        uint64           // Generation counter for racing deadline updates while a read wait is in flight.
}

type packetConnStream struct {
	net.PacketConn
	remote net.Addr
}

type readDeadlineKind uint8

const (
	readDeadlineNone readDeadlineKind = iota
	readDeadlineUserRead
	readDeadlineUserWrite
)

var boringSSLCipherSuiteNames = map[dtls.CipherSuiteID]string{
	dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:        "ECDHE-ECDSA-AES128-CCM",
	dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:      "ECDHE-ECDSA-AES128-CCM8",
	dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "ECDHE-ECDSA-AES128-GCM-SHA256",
	dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "ECDHE-ECDSA-AES256-GCM-SHA384",
	dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "ECDHE-RSA-AES128-GCM-SHA256",
	dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "ECDHE-RSA-AES256-GCM-SHA384",
	dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    "ECDHE-ECDSA-AES256-SHA",
	dtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "ECDHE-RSA-AES256-SHA",
}

var boringSSLSRTPProfileNames = map[dtls.SRTPProtectionProfile]string{
	dtls.SRTP_AEAD_AES_128_GCM:       "SRTP_AEAD_AES_128_GCM",
	dtls.SRTP_AEAD_AES_256_GCM:       "SRTP_AEAD_AES_256_GCM",
	dtls.SRTP_AES128_CM_HMAC_SHA1_80: "SRTP_AES128_CM_SHA1_80",
	dtls.SRTP_NULL_HMAC_SHA1_80:      "SRTP_NULL_SHA1_80",
}

var boringSSLSelectedSRTPProfiles = map[C.ulong]dtls.SRTPProtectionProfile{
	C.SRTP_AEAD_AES_128_GCM:  dtls.SRTP_AEAD_AES_128_GCM,
	C.SRTP_AEAD_AES_256_GCM:  dtls.SRTP_AEAD_AES_256_GCM,
	C.SRTP_AES128_CM_SHA1_80: dtls.SRTP_AES128_CM_HMAC_SHA1_80,
	C.SRTP_NULL_SHA1_80:      dtls.SRTP_NULL_HMAC_SHA1_80,
}
var bioStreamMethodOnce sync.Once

func packetConnAsConn(conn net.PacketConn, remote net.Addr) net.Conn {
	if c, ok := conn.(net.Conn); ok && c.RemoteAddr() != nil {
		return c
	}
	return &packetConnStream{PacketConn: conn, remote: remote}
}

func (c *packetConnStream) Read(p []byte) (int, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, err
		}
		if c.remote == nil {
			return n, nil
		}
		if addr != nil && addr.Network() == c.remote.Network() && addr.String() == c.remote.String() {
			return n, nil
		}
	}
}

func (c *packetConnStream) Write(p []byte) (int, error) {
	if c.remote == nil {
		return 0, errors.New("boringssl: missing remote address")
	}
	return c.PacketConn.WriteTo(p, c.remote)
}

func (c *packetConnStream) RemoteAddr() net.Addr {
	return c.remote
}

func newBoringSSLConn(conn net.Conn, cfg *dtls.Config, isClient bool) (*boringSSLConn, error) {
	if cfg == nil {
		return nil, errors.New("boringssl: nil dtls config")
	}

	for _, check := range []struct {
		unsupported bool
		field       string
	}{
		{cfg.CustomCipherSuites != nil, "cfg.CustomCipherSuites"},
		{len(cfg.SignatureSchemes) > 0, "cfg.SignatureSchemes"},
		{len(cfg.SRTPMasterKeyIdentifier) > 0, "cfg.SRTPMasterKeyIdentifier"},
		{cfg.DisableRetransmitBackoff, "cfg.DisableRetransmitBackoff"},
		{cfg.PSK != nil, "cfg.PSK"},
		{len(cfg.PSKIdentityHint) > 0, "cfg.PSKIdentityHint"},
		{cfg.InsecureHashes, "cfg.InsecureHashes"},
		{isClient && !cfg.InsecureSkipVerify, "cfg.InsecureSkipVerify=false"},
		{cfg.VerifyConnection != nil, "cfg.VerifyConnection"},
		{cfg.RootCAs != nil, "cfg.RootCAs"},
		{cfg.ClientCAs != nil, "cfg.ClientCAs"},
		{!isClient && !cfg.InsecureSkipVerifyHello, "server-side DTLS cookie exchange (cfg.InsecureSkipVerifyHello=false)"},
		{cfg.ServerName != "", "cfg.ServerName"},
		{cfg.KeyLogWriter != nil, "cfg.KeyLogWriter"},
		{cfg.SessionStore != nil, "cfg.SessionStore"},
		{len(cfg.SupportedProtocols) > 0, "cfg.SupportedProtocols"},
		{cfg.GetCertificate != nil, "cfg.GetCertificate"},
		{cfg.GetClientCertificate != nil, "cfg.GetClientCertificate"},
		{cfg.ConnectionIDGenerator != nil, "cfg.ConnectionIDGenerator"},
		{cfg.PaddingLengthGenerator != nil, "cfg.PaddingLengthGenerator"},
		{cfg.HelloRandomBytesGenerator != nil, "cfg.HelloRandomBytesGenerator"},
		{cfg.ClientHelloMessageHook != nil, "cfg.ClientHelloMessageHook"},
		{cfg.ServerHelloMessageHook != nil, "cfg.ServerHelloMessageHook"},
		{cfg.CertificateRequestMessageHook != nil, "cfg.CertificateRequestMessageHook"},
		{cfg.OnConnectionAttempt != nil, "cfg.OnConnectionAttempt"},
		{cfg.ExtendedMasterSecret != dtls.RequestExtendedMasterSecret, "cfg.ExtendedMasterSecret"},
		{cfg.FlightInterval != 0, "cfg.FlightInterval"},
		{cfg.ReplayProtectionWindow != 0, "cfg.ReplayProtectionWindow"},
		{!isClient && (cfg.ClientAuth == dtls.VerifyClientCertIfGiven || cfg.ClientAuth == dtls.RequireAndVerifyClientCert), "cfg.ClientAuth value that requires certificate chain verification"},
	} {
		if check.unsupported {
			return nil, boringSSLUnsupported(check.field)
		}
	}

	ctx := C.SSL_CTX_new(C.DTLS_method())
	if ctx == nil {
		return nil, errorFromBoringSSLErrors()
	}
	failCtx := func(err error) (*boringSSLConn, error) {
		C.SSL_CTX_free(ctx)
		return nil, err
	}
	C.SSL_CTX_set_min_proto_version(ctx, C.DTLS1_2_VERSION)
	C.SSL_CTX_set_max_proto_version(ctx, C.DTLS1_3_VERSION)
	curveNames := make([]string, 0, len(cfg.EllipticCurves))
	for _, curve := range cfg.EllipticCurves {
		switch curve {
		case dtlsElliptic.X25519, dtlsElliptic.P256, dtlsElliptic.P384:
			curveNames = append(curveNames, curve.String())
		default:
			return failCtx(fmt.Errorf("boringssl: unsupported cfg.EllipticCurve %s", curve.String()))
		}
	}
	curveList := "X25519:P-256:P-384"
	if len(curveNames) > 0 {
		curveList = strings.Join(curveNames, ":")
	}
	groups := C.CString(curveList)
	defer C.free(unsafe.Pointer(groups))
	if C.SSL_CTX_set1_groups_list(ctx, groups) != 1 {
		return failCtx(errorFromBoringSSLErrors())
	}
	C.SSL_CTX_set_options(ctx, C.uint32_t(C.SSL_OP_NO_TICKET|C.SSL_OP_NO_QUERY_MTU))
	verifyMode := C.int(C.SSL_VERIFY_NONE)
	if !isClient {
		switch cfg.ClientAuth {
		case dtls.NoClientCert:
			verifyMode = C.SSL_VERIFY_NONE
		case dtls.RequestClientCert:
			verifyMode = C.SSL_VERIFY_PEER
		case dtls.RequireAnyClientCert:
			verifyMode = C.SSL_VERIFY_PEER | C.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
		default:
			verifyMode = C.SSL_VERIFY_NONE
		}
	}
	C.webrtc_ssl_ctx_set_verify(ctx, verifyMode)

	if len(cfg.CipherSuites) > 0 {
		cipherNames := make([]string, 0, len(cfg.CipherSuites))
		for _, id := range cfg.CipherSuites {
			name, ok := boringSSLCipherSuiteNames[id]
			if !ok {
				return failCtx(fmt.Errorf("boringssl: unsupported cfg.CipherSuite %#x", uint16(id)))
			}
			cipherNames = append(cipherNames, name)
		}
		cipherList := strings.Join(cipherNames, ":")
		ccipherList := C.CString(cipherList)
		defer C.free(unsafe.Pointer(ccipherList))
		if C.SSL_CTX_set_strict_cipher_list(ctx, ccipherList) != 1 {
			return failCtx(errorFromBoringSSLErrors())
		}
	}

	if len(cfg.Certificates) == 0 {
		return failCtx(errors.New("boringssl: no local certificates configured"))
	}
	if len(cfg.Certificates) > 1 {
		return failCtx(errors.New("boringssl: multiple local certificates are not supported"))
	}
	tlsCert := cfg.Certificates[0]
	if len(tlsCert.Certificate) == 0 {
		return failCtx(errors.New("boringssl: missing certificate data"))
	}
	if len(tlsCert.Certificate) > 1 {
		return failCtx(errors.New("boringssl: certificate chains are not supported"))
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Certificate[0]})
	if len(certPEM) == 0 {
		return failCtx(errors.New("boringssl: failed to encode certificate"))
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(tlsCert.PrivateKey)
	if err != nil {
		return failCtx(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if len(keyPEM) == 0 {
		return failCtx(errors.New("boringssl: failed to encode private key"))
	}
	certPEMBytes := C.CBytes(certPEM)
	defer C.free(certPEMBytes)
	certBio := C.BIO_new_mem_buf(certPEMBytes, C.long(len(certPEM)))
	if certBio == nil {
		return failCtx(errors.New("boringssl: failed to create cert BIO"))
	}
	defer C.BIO_free(certBio)
	x509Cert := C.PEM_read_bio_X509(certBio, nil, nil, nil)
	if x509Cert == nil {
		return failCtx(errorFromBoringSSLErrors())
	}
	defer C.X509_free(x509Cert)
	if C.SSL_CTX_use_certificate(ctx, x509Cert) != 1 {
		return failCtx(errorFromBoringSSLErrors())
	}
	keyPEMBytes := C.CBytes(keyPEM)
	defer C.free(keyPEMBytes)
	keyBio := C.BIO_new_mem_buf(keyPEMBytes, C.long(len(keyPEM)))
	if keyBio == nil {
		return failCtx(errors.New("boringssl: failed to create key BIO"))
	}
	defer C.BIO_free(keyBio)
	pkey := C.PEM_read_bio_PrivateKey(keyBio, nil, nil, nil)
	if pkey == nil {
		return failCtx(errorFromBoringSSLErrors())
	}
	defer C.EVP_PKEY_free(pkey)
	if C.SSL_CTX_use_PrivateKey(ctx, pkey) != 1 {
		return failCtx(errorFromBoringSSLErrors())
	}
	if C.SSL_CTX_check_private_key(ctx) != 1 {
		return failCtx(errorFromBoringSSLErrors())
	}

	srtpNames := make([]string, 0, len(cfg.SRTPProtectionProfiles))
	for _, p := range cfg.SRTPProtectionProfiles {
		name, ok := boringSSLSRTPProfileNames[p]
		if !ok {
			return failCtx(fmt.Errorf("boringssl: unsupported cfg.SRTPProtectionProfile %#x", uint16(p)))
		}
		srtpNames = append(srtpNames, name)
	}
	srtpList := strings.Join(srtpNames, ":")
	if srtpList == "" {
		return failCtx(errors.New("boringssl: no SRTP profiles configured"))
	}
	cnames := C.CString(srtpList)
	defer C.free(unsafe.Pointer(cnames))
	if C.SSL_CTX_set_srtp_profiles(ctx, cnames) != 1 {
		return failCtx(errorFromBoringSSLErrors())
	}

	ssl := C.SSL_new(ctx)
	if ssl == nil {
		return failCtx(errorFromBoringSSLErrors())
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1200
	}
	C.SSL_set_mtu(ssl, C.uint(mtu))
	C.SSL_set_mode(ssl, C.SSL_MODE_ENABLE_PARTIAL_WRITE|C.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)

	readBio := C.BIO_new(C.BIO_s_mem())
	if readBio == nil {
		C.SSL_free(ssl)
		C.SSL_CTX_free(ctx)
		return nil, errors.New("boringssl: failed to create read BIO")
	}
	bioStreamMethodOnce.Do(func() {
		C.init_stream_method()
	})
	writeBio := C.BIO_new_stream()
	if writeBio == nil {
		C.BIO_free(readBio)
		C.SSL_free(ssl)
		C.SSL_CTX_free(ctx)
		return nil, errors.New("boringssl: failed to create write BIO")
	}

	bc := &boringSSLConn{
		Conn:    conn,
		ssl:     ssl,
		ctx:     ctx,
		readBio: readBio,
		verify:  cfg.VerifyPeerCertificate,
		mtu:     mtu,
	}
	bc.handle = cgo.NewHandle(bc)
	bc.handlePtr = C.malloc(C.size_t(unsafe.Sizeof(C.uintptr_t(0))))
	if bc.handlePtr == nil {
		bc.handle.Delete()
		C.BIO_free(writeBio)
		C.BIO_free(readBio)
		C.SSL_free(ssl)
		C.SSL_CTX_free(ctx)
		return nil, errors.New("boringssl: failed to allocate BIO callback handle")
	}
	*(*C.uintptr_t)(bc.handlePtr) = C.uintptr_t(bc.handle)
	C.BIO_set_data(writeBio, bc.handlePtr)

	C.SSL_set_bio(ssl, readBio, writeBio)

	if isClient {
		C.SSL_set_connect_state(ssl)
	} else {
		C.SSL_set_accept_state(ssl)
	}

	return bc, nil
}

func (c *boringSSLConn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

func (c *boringSSLConn) HandshakeContext(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.profile != 0 {
		return nil
	}
	if c.closed {
		return io.ErrClosedPipe
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.clearLastWriteError()
		ret := C.SSL_do_handshake(c.ssl)
		if ret == 1 {
			break
		}

		errCode := C.SSL_get_error(c.ssl, ret)
		switch errCode {
		case C.SSL_ERROR_WANT_READ:
			if err := c.readRecord(ctx, readDeadlineNone); err != nil {
				return err
			}
		case C.SSL_ERROR_WANT_WRITE:
			continue
		case C.SSL_ERROR_ZERO_RETURN:
			return io.EOF
		default:
			if err := c.takeLastWriteError(); err != nil {
				return err
			}
			return errorFromBoringSSLErrors()
		}
	}

	if c.verify != nil {
		var rawCerts [][]byte
		var certPtr *C.uint8_t
		var certLen C.size_t
		if C.webrtc_ssl_get_peer_cert_der(c.ssl, &certPtr, &certLen) == 1 {
			rawCerts = [][]byte{C.GoBytes(unsafe.Pointer(certPtr), C.int(certLen))}
			C.webrtc_ssl_free(unsafe.Pointer(certPtr))
		}
		if len(rawCerts) > 0 {
			// For the supported config subset, pion/dtls invokes VerifyPeerCertificate
			// with verifiedChains=nil and only when the peer actually sent a certificate.
			if err := c.verify(rawCerts, nil); err != nil {
				return err
			}
		}
	}

	var id C.ulong
	if C.webrtc_ssl_get_selected_srtp_profile(c.ssl, &id) != 1 {
		return ErrNoSRTPProtectionProfile
	}
	profile, ok := boringSSLSelectedSRTPProfiles[id]
	if !ok {
		return ErrNoSRTPProtectionProfile
	}
	c.profile = profile

	return nil
}

func (c *boringSSLConn) readRecord(ctx context.Context, deadlineKind readDeadlineKind) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	var opDeadline time.Time
	c.deadlineMu.Lock()
	switch deadlineKind {
	case readDeadlineUserRead:
		opDeadline = c.readDeadline
	case readDeadlineUserWrite:
		opDeadline = c.writeDeadline
	}
	c.deadlineMu.Unlock()
	if deadlineExceeded(opDeadline) {
		return os.ErrDeadlineExceeded
	}

	var tv C.struct_timeval
	var dtlsDeadline time.Time
	hasTimeout := C.DTLSv1_get_timeout(c.ssl, &tv) == 1
	if hasTimeout {
		timeout := time.Duration(tv.tv_sec)*time.Second + time.Duration(tv.tv_usec)*time.Microsecond
		dtlsDeadline = time.Now().Add(timeout)
	}
	ctxDeadline, _ := ctx.Deadline()
	timeoutIsDTLS := hasTimeout &&
		(opDeadline.IsZero() || dtlsDeadline.Before(opDeadline)) &&
		(ctxDeadline.IsZero() || dtlsDeadline.Before(ctxDeadline))

	c.deadlineMu.Lock()
	c.readDeadlineSeq++
	opSeq := c.readDeadlineSeq
	c.activeReadDeadlineKind = deadlineKind
	c.activeReadOpDeadline = opDeadline
	c.internalReadDeadline = minNonZero(ctxDeadline, dtlsDeadline)
	_ = c.applyReadDeadlineLocked()
	c.deadlineMu.Unlock()

	var stopCtxCancel func() bool
	if ctx.Done() != nil {
		stopCtxCancel = context.AfterFunc(ctx, func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			if c.readDeadlineSeq != opSeq {
				return
			}

			c.internalReadDeadline = time.Now()
			_ = c.applyReadDeadlineLocked()
		})
	}
	defer func() {
		if stopCtxCancel != nil {
			stopCtxCancel()
		}
		c.deadlineMu.Lock()
		defer c.deadlineMu.Unlock()
		if c.readDeadlineSeq != opSeq {
			return
		}

		c.readDeadlineSeq++
		c.activeReadDeadlineKind = readDeadlineNone
		c.activeReadOpDeadline = time.Time{}
		c.internalReadDeadline = time.Time{}
		_ = c.applyReadDeadlineLocked()
	}()

	buf := make([]byte, 2048)
	c.readMu.Lock()
	n, err := c.Conn.Read(buf)
	c.readMu.Unlock()
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if c.isDeadlineExceeded(deadlineKind) {
				return os.ErrDeadlineExceeded
			}
			if timeoutIsDTLS {
				C.DTLSv1_handle_timeout(c.ssl)
				return nil
			}
		}
		return err
	}

	if n > 0 {
		if C.BIO_write(c.readBio, unsafe.Pointer(&buf[0]), C.int(n)) <= 0 {
			return errorFromBoringSSLErrors()
		}
	}

	return nil
}

func (c *boringSSLConn) KeyingMaterialExporter() (srtp.KeyingMaterialExporter, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c, c.profile != 0
}

func (c *boringSSLConn) SelectedSRTPProtectionProfile() (dtls.SRTPProtectionProfile, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.profile, c.profile != 0
}

func (c *boringSSLConn) negotiatedVersion() int {
	return int(C.SSL_version(c.ssl))
}

func (c *boringSSLConn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("boringssl: invalid keying material length")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, io.ErrClosedPipe
	}

	out := make([]byte, length)
	lbl := C.CString(label)
	defer C.free(unsafe.Pointer(lbl))

	var ctxPtr *C.uint8_t
	ctxLen := C.size_t(0)
	useCtx := C.int(0)
	if len(context) > 0 {
		ctxPtr = (*C.uint8_t)(unsafe.Pointer(&context[0]))
		ctxLen = C.size_t(len(context))
		useCtx = 1
	}

	ok := C.SSL_export_keying_material(
		c.ssl,
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		C.size_t(len(out)),
		lbl,
		C.size_t(len(label)),
		ctxPtr,
		ctxLen,
		useCtx,
	)
	if ok != 1 {
		return nil, errorFromBoringSSLErrors()
	}

	return out, nil
}

func (c *boringSSLConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if c.isDeadlineExceeded(readDeadlineUserRead) {
		return 0, os.ErrDeadlineExceeded
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}

	for {
		c.clearLastWriteError()
		if c.isDeadlineExceeded(readDeadlineUserRead) {
			return 0, os.ErrDeadlineExceeded
		}
		n := C.SSL_read(c.ssl, unsafe.Pointer(&p[0]), C.int(len(p)))
		if n > 0 {
			return int(n), nil
		}

		errCode := C.SSL_get_error(c.ssl, n)
		switch errCode {
		case C.SSL_ERROR_WANT_READ:
			if err := c.readRecord(context.Background(), readDeadlineUserRead); err != nil {
				return 0, err
			}
		case C.SSL_ERROR_WANT_WRITE:
			continue
		case C.SSL_ERROR_ZERO_RETURN:
			return 0, io.EOF
		default:
			if err := c.takeLastWriteError(); err != nil {
				return 0, err
			}
			return 0, errorFromBoringSSLErrors()
		}
	}
}

func (c *boringSSLConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.isDeadlineExceeded(readDeadlineUserWrite) {
		return 0, os.ErrDeadlineExceeded
	}
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}

	for {
		c.clearLastWriteError()
		if c.isDeadlineExceeded(readDeadlineUserWrite) {
			return 0, os.ErrDeadlineExceeded
		}
		n := C.SSL_write(c.ssl, unsafe.Pointer(&p[0]), C.int(len(p)))
		if n > 0 {
			return int(n), nil
		}

		errCode := C.SSL_get_error(c.ssl, n)
		switch errCode {
		case C.SSL_ERROR_WANT_READ:
			if err := c.readRecord(context.Background(), readDeadlineUserWrite); err != nil {
				return 0, err
			}
		case C.SSL_ERROR_WANT_WRITE:
			continue
		case C.SSL_ERROR_ZERO_RETURN:
			return 0, io.EOF
		default:
			if err := c.takeLastWriteError(); err != nil {
				return 0, err
			}
			return 0, errorFromBoringSSLErrors()
		}
	}
}

func (c *boringSSLConn) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		_ = c.SetReadDeadline(time.Now())
		if c.Conn != nil {
			closeErr = c.Conn.Close()
		}

		c.mu.Lock()
		defer c.mu.Unlock()

		c.closed = true
		if c.ssl != nil {
			C.SSL_free(c.ssl)
			c.ssl = nil
		}
		if c.ctx != nil {
			C.SSL_CTX_free(c.ctx)
			c.ctx = nil
		}
		if c.handlePtr != nil {
			C.free(c.handlePtr)
			c.handlePtr = nil
		}
		if c.handle != 0 {
			c.handle.Delete()
			c.handle = 0
		}
	})

	return closeErr
}

func (c *boringSSLConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}

	return c.SetWriteDeadline(t)
}

func (c *boringSSLConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	c.readDeadline = t
	if c.activeReadDeadlineKind == readDeadlineUserRead {
		c.activeReadOpDeadline = t
	}

	return c.applyReadDeadlineLocked()
}

func (c *boringSSLConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	c.writeDeadline = t
	if c.activeReadDeadlineKind == readDeadlineUserWrite {
		c.activeReadOpDeadline = t
	}

	return c.applyReadDeadlineLocked()
}

//export go_boringssl_write_callback
func go_boringssl_write_callback(ctx unsafe.Pointer, buf *C.char, n C.int) C.int {
	if ctx == nil {
		return -1
	}
	handle := cgo.Handle(*(*C.uintptr_t)(ctx))
	conn, ok := handle.Value().(*boringSSLConn)
	if !ok {
		return -1
	}
	if n <= 0 {
		return 0
	}
	data := C.GoBytes(unsafe.Pointer(buf), n)

	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	conn.lastWriteErr = nil
	if conn.isDeadlineExceeded(readDeadlineUserWrite) {
		conn.lastWriteErr = os.ErrDeadlineExceeded
		return -1
	}
	written, err := conn.Conn.Write(data)
	if err != nil {
		conn.lastWriteErr = err
		return -1
	}
	return C.int(written)
}

//export go_boringssl_flush_callback
func go_boringssl_flush_callback(ctx unsafe.Pointer) {
	if ctx == nil {
		return
	}
	handle := cgo.Handle(*(*C.uintptr_t)(ctx))
	conn, ok := handle.Value().(*boringSSLConn)
	if !ok {
		return
	}
	if flusher, ok := conn.Conn.(interface{ Flush() error }); ok {
		_ = flusher.Flush()
	}
}

//export go_boringssl_query_mtu_callback
func go_boringssl_query_mtu_callback(ctx unsafe.Pointer) C.int {
	if ctx == nil {
		return C.int(1200)
	}
	handle := cgo.Handle(*(*C.uintptr_t)(ctx))
	conn, ok := handle.Value().(*boringSSLConn)
	if !ok || conn == nil || conn.mtu <= 0 {
		return C.int(1200)
	}

	return C.int(conn.mtu)
}

func minNonZero(ts ...time.Time) time.Time {
	var out time.Time
	for _, t := range ts {
		if t.IsZero() {
			continue
		}
		if out.IsZero() || t.Before(out) {
			out = t
		}
	}

	return out
}

func deadlineExceeded(deadline time.Time) bool {
	return !deadline.IsZero() && !time.Now().Before(deadline)
}

func (c *boringSSLConn) applyReadDeadlineLocked() error {
	if c.Conn == nil {
		return nil
	}

	return c.Conn.SetReadDeadline(minNonZero(c.activeReadOpDeadline, c.internalReadDeadline))
}

func (c *boringSSLConn) isDeadlineExceeded(deadlineKind readDeadlineKind) bool {
	if deadlineKind == readDeadlineNone {
		return false
	}

	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	switch deadlineKind {
	case readDeadlineUserRead:
		return deadlineExceeded(c.readDeadline)
	case readDeadlineUserWrite:
		return deadlineExceeded(c.writeDeadline)
	default:
		return false
	}
}

func (c *boringSSLConn) clearLastWriteError() {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.lastWriteErr = nil
}

func (c *boringSSLConn) takeLastWriteError() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	err := c.lastWriteErr
	c.lastWriteErr = nil

	return err
}

func boringSSLUnsupported(field string) error {
	return errors.New("boringssl: " + field + " is not supported")
}

func errorFromBoringSSLErrors() error {
	var errs []string
	for {
		err := C.ERR_get_error()
		if err == 0 {
			break
		}
		errs = append(errs, fmt.Sprintf("%s:%s",
			C.GoString(C.ERR_lib_error_string(err)),
			C.GoString(C.ERR_reason_error_string(err)),
		))
	}
	if len(errs) == 0 {
		return errors.New("boringssl: unknown error")
	}
	return errors.New("boringssl: " + strings.Join(errs, "; "))
}
