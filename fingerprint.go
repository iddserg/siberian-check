package main

import (
	"fmt"
	"sort"
	"strings"

	tls "github.com/refraction-networking/utls"
)

// fingerprints mirrors the set supported by dpi-ch's siberian-fingerprint option.
var fingerprints = map[string]tls.ClientHelloID{
	"chrome":  tls.HelloChrome_Auto,
	"firefox": tls.HelloFirefox_Auto,
	"safari":  tls.HelloSafari_Auto,
	"ios":     tls.HelloIOS_Auto,
	"android": tls.HelloAndroid_11_OkHttp,
	"edge":    tls.HelloEdge_Auto,
	"360":     tls.Hello360_Auto,
	"qq":      tls.HelloQQ_Auto,
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
