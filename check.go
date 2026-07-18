package main

import (
	"context"
	"net"
	"time"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/sync/errgroup"
)

type attempt struct {
	Sni       string `json:"sni"`
	ConnCount int    `json:"conn_count"`
	Error     string `json:"error,omitempty"`
}

// SiberianResult is one fingerprint's test outcome against a single IP.
type SiberianResult struct {
	Fingerprint string    `json:"fingerprint"`
	ConnCount   int       `json:"conn_count"`
	Alpha       attempt   `json:"alpha"`
	Beta        attempt   `json:"beta"`
	RetriedReal bool      `json:"retried_with_real_sni"`
	Detected    bool      `json:"siberian_detected"`
	DurationMs  int64     `json:"duration_ms"`
	StartedAt   time.Time `json:"started_at"`
}

type checkOpt struct {
	Ctx            context.Context
	IP             net.IP
	Port           int
	FingerprintKey string
	ConnCount      int
	RealSni        string // used as an alpha fallback SNI if random SNIs trip up the server itself
	TcpConnTimeout time.Duration
	TlsTimeout     time.Duration
}

// runSiberianCheck reproduces dpi-ch's webhostSiberianCheck: it fires
// ConnCount parallel TLS handshakes at the same random SNI (alpha) and a
// single handshake at a different random SNI (beta). A censor that enforces
// the "siberian" restriction throttles the burst under alpha's SNI while
// leaving beta's fresh SNI untouched - so alpha failing while beta succeeds
// (or both timing out identically) is the signature we're looking for.
func runSiberianCheck(opt checkOpt) SiberianResult {
	start := time.Now()
	fp := fingerprints[opt.FingerprintKey]

	res := SiberianResult{
		Fingerprint: opt.FingerprintKey,
		ConnCount:   opt.ConnCount,
		StartedAt:   start,
	}

	alphaSni := randomHostname()
	betaSni := randomHostname()

	alphaErr := burstHandshake(opt, fp, alphaSni, opt.ConnCount)
	betaErr := burstHandshake(opt, fp, betaSni, 1)

	// Some servers themselves reject unrecognized/random SNIs (e.g. strict
	// SNI whitelisting), which would look identical to a "siberian" alpha
	// failure. In that case, retry alpha with the real domain SNI and beta
	// with an empty SNI (empty SNI is not known to trigger the restriction).
	if alphaErr == errTlsInternal || betaErr == errTlsInternal {
		res.RetriedReal = true
		alphaSni = opt.RealSni
		betaSni = ""
		alphaErr = burstHandshake(opt, fp, alphaSni, opt.ConnCount)
		betaErr = burstHandshake(opt, fp, betaSni, 1)
	}

	res.Alpha = attempt{Sni: alphaSni, ConnCount: opt.ConnCount, Error: errString(alphaErr)}
	res.Beta = attempt{Sni: betaSni, ConnCount: 1, Error: errString(betaErr)}

	res.Detected = (alphaErr != nil && betaErr == nil) ||
		(alphaErr == errTlsHandshakeTimeout && betaErr == errTlsHandshakeTimeout)

	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

// burstHandshake fires `count` parallel TLS handshakes at the same SNI/IP and
// returns the first error encountered (nil if all of them succeeded).
func burstHandshake(opt checkOpt, fp tls.ClientHelloID, sni string, count int) error {
	ctx := opt.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	g, gctx := errgroup.WithContext(ctx)

	for range count {
		g.Go(func() error {
			return tlsHandshakeOnce(dialOpt{
				Ctx:            gctx,
				IP:             opt.IP,
				Port:           opt.Port,
				Sni:            sni,
				Fingerprint:    fp,
				TcpConnTimeout: opt.TcpConnTimeout,
				TlsTimeout:     opt.TlsTimeout,
			})
		})
	}
	return g.Wait()
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
