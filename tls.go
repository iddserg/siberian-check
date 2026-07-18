package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
)

// Error classes, mirroring dpi-ch's inetutil error taxonomy closely enough to
// reproduce the same alpha/beta detection logic.
var (
	errTcpConnTimeout      = errors.New("tcp: connection timeout")
	errTlsHandshakeTimeout = errors.New("tls: handshake timeout")
	errTlsHandshakeFail    = errors.New("tls: handshake failure")
	errTlsInternal         = errors.New("tls: internal error")
	errTlsBadRecordMac     = errors.New("tls: bad record MAC")
	errTlsInvalidKeyShare  = errors.New("tls: invalid key share")
	errTcpConnReset        = errors.New("tcp: connection reset")
	errTlsWriteBrokenPipe  = errors.New("tls: broken write pipe")
)

type dialOpt struct {
	Ctx            context.Context
	IP             net.IP
	Port           int
	Sni            string
	Fingerprint    tls.ClientHelloID
	TcpConnTimeout time.Duration
	TlsTimeout     time.Duration
}

// tlsHandshakeOnce opens a fresh TCP connection and performs a single TLS
// handshake with the given uTLS fingerprint and SNI, then closes it.
// It intentionally does not send any HTTP request - only the handshake matters
// for the "siberian" restriction check.
func tlsHandshakeOnce(opt dialOpt) error {
	dialer := net.Dialer{Timeout: opt.TcpConnTimeout}
	addr := net.JoinHostPort(opt.IP.String(), strconv.Itoa(opt.Port))

	tcpConn, err := dialer.DialContext(opt.Ctx, "tcp", addr)
	if err != nil {
		if isTimeoutErr(err) {
			return errTcpConnTimeout
		}
		if classified, ok := classifyErr(err); ok {
			return classified
		}
		return fmt.Errorf("tcp: %w", err)
	}
	defer tcpConn.Close()

	tlsConf := &tls.Config{InsecureSkipVerify: true}
	if opt.Sni != "" {
		tlsConf.ServerName = opt.Sni
	}

	uconn := tls.UClient(tcpConn, tlsConf, tls.HelloCustom)
	spec, err := tls.UTLSIdToSpec(opt.Fingerprint)
	if err != nil {
		return fmt.Errorf("fingerprint: %w", err)
	}
	// OriginalAlpn: keep the fingerprint's native ALPN list untouched (e.g.
	// h2+http/1.1 for chrome) - dpi-ch does the same for the siberian check,
	// since forcing http/1.1 alters the fingerprint censors match against.
	if err := uconn.ApplyPreset(&spec); err != nil {
		return fmt.Errorf("fingerprint: %w", err)
	}

	if opt.TlsTimeout != 0 {
		uconn.SetDeadline(time.Now().Add(opt.TlsTimeout))
		defer uconn.SetDeadline(time.Time{})
	}

	if err := uconn.HandshakeContext(opt.Ctx); err != nil {
		if isTimeoutErr(err) {
			return errTlsHandshakeTimeout
		}
		if classified, ok := classifyErr(err); ok {
			return classified
		}
		return fmt.Errorf("tls: %w", err)
	}
	uconn.Close()
	return nil
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

// classifyErr maps low-level TLS/TCP error strings onto the same coarse
// buckets dpi-ch uses, so the alpha/beta comparison behaves identically.
func classifyErr(err error) (error, bool) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "handshake failure"):
		return errTlsHandshakeFail, true
	case strings.Contains(msg, "tls: internal error"):
		return errTlsInternal, true
	case strings.Contains(msg, "bad record MAC"):
		return errTlsBadRecordMac, true
	case strings.Contains(msg, "invalid server key share"):
		return errTlsInvalidKeyShare, true
	case strings.Contains(msg, "connection reset"):
		return errTcpConnReset, true
	case strings.Contains(msg, "write: broken pipe"):
		return errTlsWriteBrokenPipe, true
	default:
		return nil, false
	}
}

const randomHostnameAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
const randomHostnameLen = 12

// randomHostname produces a random *.com label used as SNI: an ISP-side
// "siberian" restriction is keyed on a specific SNI, so a fresh random one
// resets any restriction context accumulated by a previous probe.
func randomHostname() string {
	b := make([]byte, randomHostnameLen)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = randomHostnameAlphabet[int(b[i])%len(randomHostnameAlphabet)]
	}
	return string(b) + ".com"
}
