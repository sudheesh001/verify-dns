package main

import (
	"github.com/miekg/dns"
	"strings"
)

func ParseAnswers(answer []dns.RR) string {
	res := make([]string, 0)
	for _, answerRR := range answer {
		if ans, ok := answerRR.(*dns.A); ok {
			res = append(res, ans.A.String())
		}
	}
	buffer := strings.Join(res, "|")
	return buffer
}

func PrepareQuestion(hostname string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	m.Id = dns.Id()
	m.RecursionDesired = true
	return m
}
