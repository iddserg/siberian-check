package main

import (
	"net"
	"testing"

	tls "github.com/refraction-networking/utls"
)

// Exercise the same preset path as the probes, including the empty-SNI retry.
// A valid ID alone does not guarantee that uTLS can build its ClientHello.
func TestFingerprintClientHellos(t *testing.T) {
	for _, name := range fingerprintNames() {
		for _, sni := range []string{"probe.example.com", ""} {
			t.Run(name+"/"+sni, func(t *testing.T) {
				spec, err := tls.UTLSIdToSpec(fingerprints[name])
				if err != nil {
					t.Fatal(err)
				}
				client, server := net.Pipe()
				defer client.Close()
				defer server.Close()
				conn := tls.UClient(client, &tls.Config{
					ServerName: sni, InsecureSkipVerify: true,
				}, tls.HelloCustom)
				if err := conn.ApplyPreset(&spec); err != nil {
					t.Fatal(err)
				}
				if err := conn.BuildHandshakeState(); err != nil {
					t.Fatal(err)
				}
				if len(conn.HandshakeState.Hello.Raw) == 0 {
					t.Fatal("empty ClientHello")
				}
			})
		}
	}
}
