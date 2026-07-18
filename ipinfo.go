package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// IPInfo holds coarse ISP/geo data about a tested IP, fetched from the free
// ip-api.com endpoint (no API key required, rate-limited to ~45 req/min).
type IPInfo struct {
	Query      string `json:"query"`
	Country    string `json:"country,omitempty"`
	RegionName string `json:"region,omitempty"`
	City       string `json:"city,omitempty"`
	ISP        string `json:"isp,omitempty"`
	Org        string `json:"org,omitempty"`
	AS         string `json:"as,omitempty"`
}

// lookupIPInfo fetches ISP/geo info for ip. Best-effort: network errors or a
// non-"success" API response are returned as an error, callers should treat
// this as optional enrichment and continue without it. An empty ip queries
// info about the caller's own outgoing public IP.
func lookupIPInfo(ctx context.Context, ip string, timeout time.Duration) (*IPInfo, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,regionName,city,isp,org,as,query", ip)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var raw struct {
		Status     string `json:"status"`
		Message    string `json:"message"`
		Country    string `json:"country"`
		RegionName string `json:"regionName"`
		City       string `json:"city"`
		ISP        string `json:"isp"`
		Org        string `json:"org"`
		AS         string `json:"as"`
		Query      string `json:"query"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	if raw.Status != "success" {
		msg := raw.Message
		if msg == "" {
			msg = "lookup failed"
		}
		return nil, fmt.Errorf("ip-api: %s", msg)
	}

	return &IPInfo{
		Query:      raw.Query,
		Country:    raw.Country,
		RegionName: raw.RegionName,
		City:       raw.City,
		ISP:        raw.ISP,
		Org:        raw.Org,
		AS:         raw.AS,
	}, nil
}
