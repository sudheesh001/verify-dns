package main

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
)

func Probe(ip net.IP, query *dns.Msg) *Telemetry {
	c := new(dns.Client)
	resp, rtt, err := c.Exchange(query, fmt.Sprintf("%v:53", ip.String()))
	if err != nil {
		return nil
	}

	t := Telemetry{
		IP:               ip.String(),
		ContainsResponse: resp.Response,
		AA:               resp.Authoritative,
		RA:               resp.RecursionAvailable,
		AD:               resp.AuthenticatedData,
		CD:               resp.CheckingDisabled,
		RCode:            resp.Rcode,
		RTT:              rtt,
		ResponseIPs:      ParseAnswers(resp.Answer),
	}

	return &t
}
