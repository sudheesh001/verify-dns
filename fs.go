package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

func ReadInputFile(filepath string) []net.IP {
	f, err := os.Open(filepath)
	if err != nil {
		panic(fmt.Sprintf("failed to open file. Error: %v\n", f))
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	results := make([]net.IP, 0)
	for scanner.Scan() {
		zmapDnsIP := net.ParseIP(scanner.Text())
		if zmapDnsIP.To4() != nil {
			results = append(results, zmapDnsIP)
		}
	}

	_ = f.Close()
	return results
}
