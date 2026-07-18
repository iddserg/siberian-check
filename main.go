// Command siberian-check is a standalone reproduction of dpi-ch's "siberian"
// DPI restriction probe (webhost checker's siberian-conn-count /
// siberian-fingerprint logic), for research/measurement purposes:
// https://habr.com/ru/articles/1044396/
//
// Given only a domain, it resolves every IP behind it and tests every
// supported TLS fingerprint against each one, then prints a report (plain
// text by default, or JSON with -json).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Report struct {
	Domain     string     `json:"domain,omitempty"`
	Port       int        `json:"port"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt time.Time  `json:"finished_at"`
	ClientInfo *IPInfo    `json:"client_info,omitempty"`
	IPs        []IPReport `json:"ips"`
	Summary    Summary    `json:"summary"`
}

// IPReport groups every fingerprint check plus optional ISP/geo and
// traceroute enrichment for a single tested IP.
type IPReport struct {
	IP              string           `json:"ip"`
	Info            *IPInfo          `json:"ip_info,omitempty"`
	InfoError       string           `json:"ip_info_error,omitempty"`
	Traceroute      []string         `json:"traceroute,omitempty"`
	TracerouteError string           `json:"traceroute_error,omitempty"`
	Checks          []SiberianResult `json:"checks"`
}

type Summary struct {
	Total        int      `json:"total_checks"`
	Detected     int      `json:"detected_count"`
	IPsAffected  []string `json:"ips_with_detection,omitempty"`
	Fingerprints []string `json:"fingerprints_triggering_detection,omitempty"`
	AnyDetected  bool     `json:"any_detected"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		domain          = flag.String("domain", "", "Domain to test (resolves all A/AAAA records unless -ip is set)")
		ipFlag          = flag.String("ip", "", "Comma-separated literal IP address(es) to test instead of resolving -domain")
		port            = flag.Int("port", 443, "TCP port to test")
		fpFlag          = flag.String("fingerprint", "all", "Comma-separated TLS fingerprint(s) to test, or \"all\": "+listFingerprints())
		connCount       = flag.Int("conn-count", 4, "siberian-conn-count: number of parallel TLS handshakes in the burst probe")
		workers         = flag.Int("workers", 4, "Max concurrent (ip, fingerprint) test pairs")
		tcpTimeout      = flag.Duration("tcp-timeout", 8*time.Second, "TCP connect timeout per handshake attempt")
		tlsTimeout      = flag.Duration("tls-timeout", 8*time.Second, "TLS handshake timeout per handshake attempt")
		output          = flag.String("output", "", "Write report to this file instead of stdout")
		asJSON          = flag.Bool("json", false, "Output machine-readable JSON instead of the default plain-text report")
		verbose         = flag.Bool("verbose", false, "Print per-check progress to stderr")
		globalTotal     = flag.Duration("total-timeout", 0, "Overall timeout for the whole run (0 = no limit)")
		noGeoIP         = flag.Bool("no-geoip", false, "Skip ISP/geo lookup (ip-api.com) for each tested IP and for your own outgoing IP")
		geoIPTimeout    = flag.Duration("geoip-timeout", 5*time.Second, "Timeout for the ISP/geo lookup per IP")
		traceroute      = flag.Bool("traceroute", false, "Also run the OS traceroute/tracert to each tested IP (off by default, slow)")
		tracerouteHops  = flag.Int("traceroute-max-hops", 20, "Max hops for traceroute")
		tracerouteTotal = flag.Duration("traceroute-timeout", 15*time.Second, "Timeout for the traceroute to each tested IP")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -domain example.com [flags]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Standalone \"siberian\" DPI restriction checker (research tool).")
		fmt.Fprintln(os.Stderr, "With only -domain given, it resolves every IP behind it and tests")
		fmt.Fprintln(os.Stderr, "every supported TLS fingerprint against each one (maximum coverage).")
		fmt.Fprintln(os.Stderr, "Prints a plain-text report by default; pass -json for machine-readable output.")
		fmt.Fprintln(os.Stderr)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *domain == "" && *ipFlag == "" {
		flag.Usage()
		return fmt.Errorf("either -domain or -ip is required")
	}

	fpNames, err := parseFingerprints(*fpFlag)
	if err != nil {
		return err
	}
	if *connCount < 1 {
		return fmt.Errorf("-conn-count must be >= 1")
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if *globalTotal > 0 {
		ctx, cancel = context.WithTimeout(ctx, *globalTotal)
		defer cancel()
	}

	var ips []net.IP
	if *ipFlag != "" {
		ips, err = parseIPs(*ipFlag)
	} else {
		ips, err = resolveIPs(ctx, *domain)
	}
	if err != nil {
		return err
	}
	if *verbose {
		fmt.Fprintf(os.Stderr, "targets: %d ip(s), %d fingerprint(s), conn-count=%d\n", len(ips), len(fpNames), *connCount)
	}

	runStarted := time.Now()

	var clientInfo *IPInfo
	var clientWg sync.WaitGroup
	if !*noGeoIP {
		clientWg.Add(1)
		go func() {
			defer clientWg.Done()
			info, err := lookupIPInfo(ctx, "", *geoIPTimeout)
			if err != nil {
				if *verbose {
					fmt.Fprintf(os.Stderr, "client ip/geo lookup failed: %s\n", err)
				}
				return
			}
			clientInfo = info
		}()
	}

	ipReports := make([]IPReport, len(ips))
	var ipWg sync.WaitGroup
	for i, ip := range ips {
		ipReports[i].IP = ip.String()
		ipReports[i].Checks = make([]SiberianResult, len(fpNames))

		if !*noGeoIP {
			ipWg.Add(1)
			go func(i int, ip net.IP) {
				defer ipWg.Done()
				info, err := lookupIPInfo(ctx, ip.String(), *geoIPTimeout)
				if err != nil {
					ipReports[i].InfoError = err.Error()
					return
				}
				ipReports[i].Info = info
			}(i, ip)
		}

		if *traceroute {
			ipWg.Add(1)
			go func(i int, ip net.IP) {
				defer ipWg.Done()
				trCtx, cancel := context.WithTimeout(ctx, *tracerouteTotal)
				defer cancel()
				lines, err := runTraceroute(trCtx, ip.String(), *tracerouteHops)
				if err != nil {
					ipReports[i].TracerouteError = err.Error()
					return
				}
				ipReports[i].Traceroute = lines
			}(i, ip)
		}
	}

	type job struct {
		ipIdx int
		ip    net.IP
		fpIdx int
		fp    string
	}
	jobs := make([]job, 0, len(ips)*len(fpNames))
	for i, ip := range ips {
		for j, fp := range fpNames {
			jobs = append(jobs, job{ipIdx: i, ip: ip, fpIdx: j, fp: fp})
		}
	}

	sem := make(chan struct{}, *workers)
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()

			if *verbose {
				fmt.Fprintf(os.Stderr, "[%s / %s] checking...\n", j.ip, j.fp)
			}

			res := runSiberianCheck(checkOpt{
				Ctx:            ctx,
				IP:             j.ip,
				Port:           *port,
				FingerprintKey: j.fp,
				ConnCount:      *connCount,
				RealSni:        *domain,
				TcpConnTimeout: *tcpTimeout,
				TlsTimeout:     *tlsTimeout,
			})
			ipReports[j.ipIdx].Checks[j.fpIdx] = res

			if *verbose {
				fmt.Fprintf(os.Stderr, "[%s / %s] detected=%v alpha_err=%q beta_err=%q\n",
					j.ip, j.fp, res.Detected, res.Alpha.Error, res.Beta.Error)
			}
		}(j)
	}
	wg.Wait()
	ipWg.Wait()
	clientWg.Wait()

	for i := range ipReports {
		sort.Slice(ipReports[i].Checks, func(a, b int) bool {
			return ipReports[i].Checks[a].Fingerprint < ipReports[i].Checks[b].Fingerprint
		})
	}
	sort.Slice(ipReports, func(a, b int) bool { return ipReports[a].IP < ipReports[b].IP })

	report := Report{
		Domain:     *domain,
		Port:       *port,
		StartedAt:  runStarted,
		FinishedAt: time.Now(),
		ClientInfo: clientInfo,
		IPs:        ipReports,
		Summary:    buildSummary(ipReports),
	}

	var out []byte
	if *asJSON {
		out, err = json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		out = append(out, '\n')
	} else {
		out = []byte(renderText(report))
	}

	if *output == "" {
		_, err = os.Stdout.Write(out)
		return err
	}
	return os.WriteFile(*output, out, 0o644)
}

func buildSummary(ipReports []IPReport) Summary {
	s := Summary{}
	ipSet := map[string]bool{}
	fpSet := map[string]bool{}
	for _, ipr := range ipReports {
		for _, r := range ipr.Checks {
			s.Total++
			if r.Detected {
				s.Detected++
				ipSet[ipr.IP] = true
				fpSet[r.Fingerprint] = true
			}
		}
	}
	for ip := range ipSet {
		s.IPsAffected = append(s.IPsAffected, ip)
	}
	for fp := range fpSet {
		s.Fingerprints = append(s.Fingerprints, fp)
	}
	sort.Strings(s.IPsAffected)
	sort.Strings(s.Fingerprints)
	s.AnyDetected = s.Detected > 0
	return s
}

func renderText(r Report) string {
	var b strings.Builder

	if r.Domain != "" {
		fmt.Fprintf(&b, "Domain:  %s\n", r.Domain)
	}
	fmt.Fprintf(&b, "Port:    %d\n", r.Port)
	fmt.Fprintf(&b, "Started: %s\n", r.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "Elapsed: %s\n", r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond))

	if r.ClientInfo != nil {
		loc := strings.Join(nonEmpty(r.ClientInfo.City, r.ClientInfo.RegionName, r.ClientInfo.Country), ", ")
		b.WriteString("\n=== Your outgoing connection ===\n")
		fmt.Fprintf(&b, "IP:       %s\n", orDash(r.ClientInfo.Query))
		fmt.Fprintf(&b, "ISP:      %s\n", orDash(r.ClientInfo.ISP))
		fmt.Fprintf(&b, "Org:      %s\n", orDash(r.ClientInfo.Org))
		fmt.Fprintf(&b, "AS:       %s\n", orDash(r.ClientInfo.AS))
		fmt.Fprintf(&b, "Location: %s\n", orDash(loc))
	}

	for _, ipr := range r.IPs {
		b.WriteString("\n")
		fmt.Fprintf(&b, "=== %s ===\n", ipr.IP)

		if ipr.Info != nil {
			loc := strings.Join(nonEmpty(ipr.Info.City, ipr.Info.RegionName, ipr.Info.Country), ", ")
			fmt.Fprintf(&b, "ISP:      %s\n", orDash(ipr.Info.ISP))
			fmt.Fprintf(&b, "Org:      %s\n", orDash(ipr.Info.Org))
			fmt.Fprintf(&b, "AS:       %s\n", orDash(ipr.Info.AS))
			fmt.Fprintf(&b, "Location: %s\n", orDash(loc))
		} else if ipr.InfoError != "" {
			fmt.Fprintf(&b, "ISP/geo:  lookup failed (%s)\n", ipr.InfoError)
		}

		if len(ipr.Traceroute) > 0 {
			b.WriteString("Traceroute:\n")
			for _, line := range ipr.Traceroute {
				fmt.Fprintf(&b, "  %s\n", line)
			}
		} else if ipr.TracerouteError != "" {
			fmt.Fprintf(&b, "Traceroute: failed (%s)\n", ipr.TracerouteError)
		}

		b.WriteString("Checks:\n")
		fmt.Fprintf(&b, "  %-8s  %-6s  %-9s  %-22s  %-22s  %s\n",
			"FINGRPT", "CONN", "SIBERIAN", "ALPHA ERR", "BETA ERR", "TIME")
		for _, c := range ipr.Checks {
			verdict := "no"
			if c.Detected {
				verdict = "YES"
			}
			fmt.Fprintf(&b, "  %-8s  %-6d  %-9s  %-22s  %-22s  %dms\n",
				c.Fingerprint, c.ConnCount, verdict, orDash(c.Alpha.Error), orDash(c.Beta.Error), c.DurationMs)
		}
	}

	b.WriteString("\n")
	if r.Summary.AnyDetected {
		fmt.Fprintf(&b, "RESULT: \"siberian\" restriction DETECTED (%d/%d checks) on IP(s) %s, fingerprint(s) %s\n",
			r.Summary.Detected, r.Summary.Total,
			strings.Join(r.Summary.IPsAffected, ", "), strings.Join(r.Summary.Fingerprints, ", "))
	} else {
		fmt.Fprintf(&b, "RESULT: no \"siberian\" restriction detected (0/%d checks)\n", r.Summary.Total)
	}

	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func nonEmpty(vals ...string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func listFingerprints() string {
	names := fingerprintNames()
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ","
		}
		out += n
	}
	return out
}
