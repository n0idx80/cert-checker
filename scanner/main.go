package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var limiter = rate.NewLimiter(rate.Limit(50), 5) // 50 requests per second, burst of 5

type CertResult struct {
	IP         string    `json:"ip"`
	HasCert    bool      `json:"has_cert"`
	Valid      bool      `json:"valid"`
	Expired    bool      `json:"expired"`
	Issuer     string    `json:"issuer"`
	CommonName string    `json:"common_name"` // Subject CN
	SANs       []string  `json:"sans"`        // Subject Alternative Names
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Error      string    `json:"error,omitempty"`
	Status     string    `json:"status,omitempty"`
}

func scanIP(target string, results chan<- CertResult, wg *sync.WaitGroup) {
	defer wg.Done()

	// Wait for rate limiter
	err := limiter.Wait(context.Background())
	if err != nil {
		// Handle rate limit error
		return
	}

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
			Timeout:   10 * time.Second, // Increased timeout
			KeepAlive: 30 * time.Second, // Added keepalive
		},
		"tcp",
		fmt.Sprintf("%s:443", host),
		&tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10, // Allow older TLS versions
			MaxVersion:         tls.VersionTLS13, // Up to latest TLS
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_RC4_128_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			}, // Explicitly list all cipher suites
			Renegotiation: tls.RenegotiateOnceAsClient, // Allow renegotiation
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

	if cert := conn.ConnectionState().PeerCertificates[0]; cert != nil {
		now := time.Now()
		result.HasCert = true
		result.Expired = now.After(cert.NotAfter)
		result.Valid = now.After(cert.NotBefore) && now.Before(cert.NotAfter)
		result.Issuer = cert.Issuer.CommonName
		result.CommonName = cert.Subject.CommonName
		result.SANs = cert.DNSNames

		// Debug logging
		fmt.Fprintf(os.Stderr, "Certificate for %s:\n", target)
		fmt.Fprintf(os.Stderr, "  Subject CN: %s\n", cert.Subject.CommonName)
		fmt.Fprintf(os.Stderr, "  SANs: %v\n", cert.DNSNames)
		fmt.Fprintf(os.Stderr, "  Organization: %v\n", cert.Subject.Organization)
		fmt.Fprintf(os.Stderr, "  Issuer: %s\n", cert.Issuer.CommonName)

		// Try to get the most meaningful name
		if result.CommonName == "" {
			// If no CN, try to get the first SAN
			if len(cert.DNSNames) > 0 {
				result.CommonName = cert.DNSNames[0]
			} else if len(cert.Subject.Organization) > 0 {
				// If no SAN, try organization name
				result.CommonName = cert.Subject.Organization[0]
			}
		}

		result.NotBefore = cert.NotBefore
		result.NotAfter = cert.NotAfter

		if result.Expired {
			result.Status = "Certificate Expired"
		} else if !result.Valid {
			result.Status = "Certificate Invalid"
		} else {
			result.Status = "Certificate Valid"
		}
	}

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
