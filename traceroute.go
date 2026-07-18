package main

import (
	"context"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// runTraceroute shells out to the OS's traceroute/tracert binary and returns
// its output as a list of trimmed, non-empty lines. This is a best-effort
// helper (no raw-socket ICMP implementation of our own) - if the binary is
// missing or the call fails, callers should just skip this enrichment.
func runTraceroute(ctx context.Context, ip string, maxHops int) ([]string, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "tracert", "-d", "-h", strconv.Itoa(maxHops), ip)
	default: // linux, darwin, etc.
		cmd = exec.CommandContext(ctx, "traceroute", "-n", "-q", "1", "-w", "1", "-m", strconv.Itoa(maxHops), ip)
	}

	out, err := cmd.CombinedOutput()
	lines := splitNonEmptyLines(string(out))
	if err != nil {
		if len(lines) > 0 {
			// traceroute often exits non-zero on partial/incomplete paths;
			// still return what it printed.
			return lines, nil
		}
		return nil, err
	}
	return lines, nil
}

func splitNonEmptyLines(s string) []string {
	raw := strings.Split(s, "\n")
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
