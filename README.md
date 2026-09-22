# siberian-check

Standalone research tool for detecting the "siberian" DPI restriction used by
some Russian ISPs — a censorship method that throttles bursts of parallel TLS
connections to the same SNI when the server sits in a "suspicious"
subnet/AS and the client's TLS fingerprint looks like a browser (Chrome,
Safari, iOS are commonly flagged; Firefox/Android usually pass).
Background: https://habr.com/ru/articles/1044396/

It's a self-contained reimplementation of the `siberian-conn-count` /
`siberian-fingerprint` check from
[dpi-ch](https://github.com/hyperion-cs/dpi-checkers)'s webhost checker,
extracted into its own CLI with extra reporting (ISP/geo lookup,
traceroute).

> For research and educational purposes only. You are responsible for
> complying with the laws of your jurisdiction.

## How the check works

For each `(IP, fingerprint)` pair:

1. Generate a random SNI (`alpha`) and fire `siberian-conn-count` parallel
   TLS handshakes at it, all with the chosen browser fingerprint (via
   [uTLS](https://github.com/refraction-networking/utls)).
2. Generate a second random SNI (`beta`) and do a single handshake with it.
3. If a censor enforces the restriction, the `alpha` burst gets throttled
   (fails or times out) while the untouched `beta` SNI still succeeds — that
   asymmetry (`alpha` fails / `beta` succeeds, or both time out identically)
   is reported as `siberian_detected: true`.
4. If the server itself is picky about unrecognized SNIs (returns a TLS
   internal error for both probes), the check retries once using the real
   domain as `alpha`'s SNI and an empty SNI for `beta`, to avoid a false
   positive.

Random SNIs are used so each probe starts from a clean restriction context
instead of tripping over state left by a previous run.

## Build

```bash
cd siberian-check
go build -o siberian-check .
```

Requires Go 1.25+. Dependencies: `github.com/refraction-networking/utls`,
`golang.org/x/sync`. TLS fingerprints use the fixed versions from
[dpi-ch](https://github.com/hyperion-cs/dpi-checkers/blob/main/ru/dpi-ch/inetutil/tls.go)
(upstream commit `bb14a51`) so results stay comparable across runs.

## Usage

By default, give it just a domain — it resolves every IP behind it (A and
AAAA) and tests every supported TLS fingerprint against each one (maximum
coverage), printing a plain-text report:

```bash
./siberian-check -domain example.com
```

Add `-json` for a machine-readable report instead of text:

```bash
./siberian-check -domain example.com -json -output result.json
```

Test one specific IP with one fingerprint and a custom connection count:

```bash
./siberian-check -ip 178.72.128.17 -fingerprint chrome -conn-count 6
```

See progress while it runs:

```bash
./siberian-check -domain example.com -verbose
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-domain` | — | Domain to test (resolves all A/AAAA records unless `-ip` is set) |
| `-ip` | — | Comma-separated literal IP(s) to test instead of resolving `-domain` |
| `-port` | `443` | TCP port to test |
| `-fingerprint` | `all` | Comma-separated fingerprint(s): `chrome,firefox,safari,ios,android,edge,360,qq`, or `all` |
| `-conn-count` | `4` | `siberian-conn-count` — parallel TLS handshakes in the burst probe |
| `-workers` | `4` | Max concurrent `(ip, fingerprint)` test pairs |
| `-tcp-timeout` | `8s` | TCP connect timeout per handshake attempt |
| `-tls-timeout` | `8s` | TLS handshake timeout per handshake attempt |
| `-total-timeout` | `0` (no limit) | Overall timeout for the whole run |
| `-json` | `false` | Output JSON instead of the default plain-text report |
| `-output` | stdout | Write the report to this file instead of stdout |
| `-verbose` | `false` | Print per-check progress to stderr |
| `-no-geoip` | `false` | Skip ISP/geo lookup ([ip-api.com](http://ip-api.com), no key required) for each tested IP and for your own outgoing IP |
| `-geoip-timeout` | `5s` | Timeout for the ISP/geo lookup per IP |
| `-traceroute` | `false` | Also run the OS `traceroute`/`tracert` to each tested IP (off by default - it's slow) |
| `-traceroute-max-hops` | `20` | Max hops for traceroute |
| `-traceroute-timeout` | `15s` | Timeout for the traceroute to each tested IP |

Include a traceroute to each tested IP (off by default, adds latency):

```bash
./siberian-check -domain example.com -traceroute
```

## Output

Plain-text mode prints your own outgoing IP/ISP/geo (so you know which
network the check ran from), then per resolved IP: ISP/org/AS/location (from
ip-api.com), an optional traceroute (`-traceroute`), and a table of
per-fingerprint results (`siberian_detected`, alpha/beta errors, timing),
followed by an overall summary line.

`-json` mode gives the same data as structured JSON:

```jsonc
{
  "domain": "example.com",
  "port": 443,
  "started_at": "...",
  "finished_at": "...",
  "client_info": { "query": "your.public.ip", "isp": "...", "as": "...", ... },
  "ips": [
    {
      "ip": "1.2.3.4",
      "ip_info": { "country": "...", "isp": "...", "as": "...", ... },
      "traceroute": ["1  ...", "2  ...", ...],
      "checks": [
        {
          "fingerprint": "chrome",
          "conn_count": 4,
          "alpha": { "sni": "...", "conn_count": 4, "error": "tls: handshake timeout" },
          "beta":  { "sni": "...", "conn_count": 1 },
          "siberian_detected": true,
          "duration_ms": 412
        }
      ]
    }
  ],
  "summary": {
    "total_checks": 8,
    "detected_count": 1,
    "ips_with_detection": ["1.2.3.4"],
    "fingerprints_triggering_detection": ["chrome"],
    "any_detected": true
  }
}
```

## Notes / limitations

- Traceroute shells out to the system's `traceroute` (Linux/macOS) or
  `tracert` (Windows) binary — it must be installed and reachable on `PATH`.
  Some hops may show up as `*` due to routers not responding to
  time-exceeded probes, or firewalls dropping them; this is normal.
- ISP/geo lookup uses the free tier of ip-api.com (no API key, ~45
  requests/min limit). If you're checking many IPs at once, expect some
  lookups to fail with a rate-limit error — that's reported per-IP and
  doesn't affect the siberian check itself.
- This tool only reproduces the "siberian" burst-probe logic from dpi-ch; it
  does not implement dpi-ch's other checks (tcp 16-20, DNS spoofing/hijack
  detection, CIDR whitelist detection, etc.). For those, use
  [dpi-ch](https://github.com/hyperion-cs/dpi-checkers) itself.
