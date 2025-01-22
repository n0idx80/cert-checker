package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type CertResult struct {
	IP        string    `json:"ip"`
	HasCert   bool      `json:"has_cert"`
	Valid     bool      `json:"valid"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Error     string    `json:"error,omitempty"`
	Status    string    `json:"status,omitempty"`
}

func scanIP(target string, results chan<- CertResult, wg *sync.WaitGroup) {
	defer wg.Done()

	result := CertResult{
		IP:      target,
		HasCert: false,
		Status:  "Unknown",
	}

	// Handle both IP and domain cases
	host := target
	if net.ParseIP(target) == nil {
		// It's a domain, try to resolve it
		ips, err := net.LookupIP(target)
		if err != nil {
			result.Error = fmt.Sprintf("DNS lookup failed: %v", err)
			result.Status = "DNS Lookup Failed"
			results <- result
			return
		}
		if len(ips) > 0 {
			host = ips[0].String()
		}
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{
			Timeout: 2 * time.Second,
		},
		"tcp",
		fmt.Sprintf("%s:443", host),
		&tls.Config{
			InsecureSkipVerify: true,
		},
	)

	if err != nil {
		result.Error = err.Error()
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.Status = "Connection Timeout"
		} else {
			result.Status = "Connection Failed"
		}
		results <- result
		return
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	result.HasCert = true
	result.Valid = time.Now().After(cert.NotBefore) && time.Now().Before(cert.NotAfter)
	result.Issuer = cert.Issuer.CommonName
	result.NotBefore = cert.NotBefore
	result.NotAfter = cert.NotAfter
	result.Status = "Certificate Found"

	results <- result
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <input_file>\n", os.Args[0])
		os.Exit(1)
	}

	file, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	var wg sync.WaitGroup
	results := make(chan CertResult, 100)
	scanner := bufio.NewScanner(file)

	// Start scanning goroutines
	for scanner.Scan() {
		target := scanner.Text()
		if target == "" {
			continue
		}
		wg.Add(1)
		go scanIP(target, results, &wg)
	}

	// Start a goroutine to close results channel when all scans complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Print results as JSON lines as they come in
	encoder := json.NewEncoder(os.Stdout)
	for result := range results {
		encoder.Encode(result)
	}
}
