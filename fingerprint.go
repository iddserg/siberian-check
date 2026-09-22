package main

import (
	"fmt"
	"sort"
	"strings"

	tls "github.com/refraction-networking/utls"
)

// fingerprints mirrors the set supported by dpi-ch's siberian-fingerprint option.
var fingerprints = map[string]tls.ClientHelloID{
	"chrome":  tls.HelloChrome_133,
	"firefox": tls.HelloFirefox_120,
	"safari":  tls.HelloSafari_16_0,
	"ios":     tls.HelloIOS_14,
	"android": tls.HelloAndroid_11_OkHttp,
	"edge":    tls.HelloEdge_85,
	"360":     tls.Hello360_7_5,
	"qq":      tls.HelloQQ_11_1,
}

func fingerprintNames() []string {
	names := make([]string, 0, len(fingerprints))
	for name := range fingerprints {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// parseFingerprints turns a comma-separated flag value into a list of fingerprint
// names. "all" (also the empty string) expands to every supported fingerprint.
func parseFingerprints(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "all") {
		return fingerprintNames(), nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		name := strings.ToLower(strings.TrimSpace(p))
		if name == "" {
			continue
		}
		if _, ok := fingerprints[name]; !ok {
			return nil, fmt.Errorf("unknown fingerprint %q (supported: %s, all)", name, strings.Join(fingerprintNames(), ", "))
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no fingerprint provided")
	}
	return out, nil
}
