package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/docker/docker/daemon/logger"
)

type HTTPSLogDriver struct {
	server    string
	port      string
	certFile  string
	keyFile   string
	caFile    string
	tlsConfig *tls.Config
}

// LogMessage defines the structure of log messages
type LogMessage struct {
	Line   string `json:"line"`
	Source string `json:"source"`
	Time   string `json:"time"`
}

func newHTTPSLogDriver(server, port, certFile, keyFile, caFile string) (*HTTPSLogDriver, error) {
	// Load client cert
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("Error loading client certificate: %v", err)
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("Error reading CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	return &HTTPSLogDriver{
		server:    server,
		port:      port,
		certFile:  certFile,
		keyFile:   keyFile,
		caFile:    caFile,
		tlsConfig: tlsConfig,
	}, nil
}

// Log forwards the log message over TLS using HTTPS
func (d *HTTPSLogDriver) Log(msg *logger.Message) error {
	logMsg := LogMessage{
		Line:   string(msg.Line),
		Source: msg.Source,
		Time:   msg.Timestamp.String(),
	}

	jsonData, err := json.Marshal(logMsg)
	if err != nil {
		return err
	}

	// Create the HTTPS client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: d.tlsConfig,
		},
	}

	// Send log message via HTTPS
	url := fmt.Sprintf("https://%s:%s/log", d.server, d.port)
	resp, err := client.Post(url, "application/json", ioutil.NopCloser(bytes.NewBuffer(jsonData)))
	if err != nil {
		return fmt.Errorf("Error forwarding log: %v", err)
	}
	defer resp.Body.Close()

	return nil
}

func (d *HTTPSLogDriver) StartLogging(source string) error {
	// This could initiate any connection or preparation needed for logging
	log.Printf("Starting logging for %s", source)
	return nil
}

func (d *HTTPSLogDriver) StopLogging(source string) error {
	log.Printf("Stopping logging for %s", source)
	return nil
}

func init() {
	if err := logger.RegisterPlugin("httpslogger", newHTTPSLogger); err != nil {
		log.Fatalf("Error registering HTTPS log driver: %v", err)
	}
}

func newHTTPSLogger(ctx logger.Context) (logger.Logger, error) {
	// Fetch log options from Docker Compose
	server := ctx.Config["server"]
	port := ctx.Config["port"]
	certFile := ctx.Config["tls_cert_file"]
	keyFile := ctx.Config["tls_key_file"]
	caFile := ctx.Config["tls_ca_file"]

	if server == "" || port == "" || certFile == "" || keyFile == "" || caFile == "" {
		return nil, errors.New("Missing required log options for HTTPS log driver")
	}

	driver, err := newHTTPSLogDriver(server, port, certFile, keyFile, caFile)
	if err != nil {
		return nil, err
	}

	return driver, nil
}
