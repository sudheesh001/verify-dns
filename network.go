package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func buildDoHQuery(host string) *url.URL {
	if !strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}
	u, _ := url.Parse(host)
	if u.Path == "" {
		u.Path = "/dns-query"
	}
	return u
}

func VerifyTLSConnection(cs tls.ConnectionState) (bool, error) {
	opts := x509.VerifyOptions{
		DNSName:       cs.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, err := cs.PeerCertificates[0].Verify(opts)
	if err != nil {
		return false, err
	}
	return true, nil
}

func parseDnsResponse(data []byte) (*dns.Msg, error) {
	msg := &dns.Msg{}
	err := msg.Unpack(data)
	return msg, err
}

func Probe(ip net.IP, query *dns.Msg, useTLS bool) *Telemetry {
	var resp *dns.Msg
	var rtt time.Duration
	var err error

	if useTLS {
		c := http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
		dohURL := buildDoHQuery(ip.String()).String()
		req, err := http.NewRequest(http.MethodGet, dohURL, nil)
		if err != nil {
			return nil
		}
		queries := req.URL.Query()
		serializedDNS, _ := query.Pack()
		encodedString := base64.RawURLEncoding.EncodeToString(serializedDNS)
		queries.Add("dns", encodedString)
		req.Header.Set("Content-Type", "application/dns-message")
		req.URL.RawQuery = queries.Encode()

		start := time.Now()
		respBytes, err := c.Do(req)
		if err != nil {
			return nil
		}
		respBodyBytes, err := io.ReadAll(respBytes.Body)
		if err != nil {
			return nil
		}
		end := time.Now()
		rtt = end.Sub(start)
		resp, err = parseDnsResponse(respBodyBytes)
	} else {
		c := new(dns.Client)
		port := "53"
		resp, rtt, err = c.Exchange(query, fmt.Sprintf("%v:%v", ip.String(), port))
	}

	if err != nil {
		fmt.Printf("%v\n", err)
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
