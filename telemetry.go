package main

import (
	"fmt"
	"time"
)

type Telemetry struct {
	IP               string
	ContainsResponse bool
	AA               bool
	RA               bool
	AD               bool
	CD               bool
	RCode            int
	RTT              time.Duration
	ResponseIPs      string
}

func TelemetryHeader() string {
	return fmt.Sprintf("%v,%v,%v,%v,%v,%v,%v,%v,%v\n",
		"IP",
		"ContainsResponse",
		"AA",
		"RA",
		"AD",
		"CD",
		"RCode",
		"RTT",
		"IPsInResponse")
}

func (t *Telemetry) Serialize() string {
	return fmt.Sprintf("%v,%v,%v,%v,%v,%v,%v,%v,%v\n",
		t.IP,
		t.ContainsResponse,
		t.AA,
		t.RA,
		t.AD,
		t.CD,
		t.RCode,
		t.RTT,
		t.ResponseIPs)
}
