package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	EULotlURL             = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
	ServiceTypeQCert      = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
	ServiceTypeQTimestamp = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QT"
	ServiceStatusGranted  = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
)

// --- XML Struct Mapping (Simplified for Extraction) ---

type TrustServiceStatusList struct {
	XMLName           xml.Name          `xml:"TrustServiceStatusList"`
	SchemeInformation SchemeInformation `xml:"SchemeInformation"`
	TSPList           []TSP             `xml:"TrustServiceProviderList>TrustServiceProvider"`
}

type SchemeInformation struct {
	Pointers []TSLPointer `xml:"PointersToOtherTSL>OtherTSLPointer"`
}

type TSLPointer struct {
	TSLLocation string `xml:"TSLLocation"`
}

type TSP struct {
	Services []TSPService `xml:"TSPServices>TSPService"`
}

type TSPService struct {
	ServiceInformation ServiceInformation `xml:"ServiceInformation"`
}

type ServiceInformation struct {
	ServiceTypeIdentifier string            `xml:"ServiceTypeIdentifier"`
	ServiceStatus         string            `xml:"ServiceStatus"`
	DigitalIdentities     []DigitalIdentity `xml:"ServiceDigitalIdentity>DigitalId"`
}

type DigitalIdentity struct {
	X509Certificate string `xml:"X509Certificate"`
}

// --- Service Implementation ---

type TLService struct {
	httpClient *http.Client
	// KeyStore holds our extracted QTSP certificates. Key could be Subject or Serial.
	// We use the Raw Base64 string as a deduplication key for simplicity here.
	CertStore map[string]*x509.Certificate
	mu        sync.RWMutex
}

func NewTLService() *TLService {
	// OBJ03: Strict TLS, trust on origin.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &TLService{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		CertStore: make(map[string]*x509.Certificate),
	}
}

// StartPeriodicSync fulfills OBJ04: A scheduled goroutine to periodically parse the TLs.
func (s *TLService) StartPeriodicSync(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			slog.Info("Starting EU LOTL Sync Cycle...")
			s.executeSync()
			slog.Info("EU LOTL Sync Cycle Complete. Sleeping...")
			<-ticker.C
		}
	}()
}

func (s *TLService) executeSync() {
	// 1. Fetch and Parse the LOTL (OBJ01)
	lotl, err := s.fetchAndParseXML(EULotlURL)
	if err != nil {
		slog.Error("Failed to fetch LOTL", "error", err)
		return
	}

	pointers := make([]string, 0)
	for _, p := range lotl.SchemeInformation.Pointers {
		pointers = append(pointers, p.TSLLocation)
	}
	slog.Info("Found number of Member State TL pointers in LOTL", "number", len(pointers))

	// 2. Concurrently fetch Member State TLs (OBJ04 - Concurrency optimization)
	var wg sync.WaitGroup
	tempStore := make(map[string]*x509.Certificate)
	var tempMu sync.Mutex

	for _, url := range pointers {
		wg.Add(1)
		go func(tlURL string) {
			defer wg.Done()

			tlData, err := s.fetchAndParseXML(tlURL)
			if err != nil {
				slog.Error("Failed to process TL", "url", tlURL, "error", err)
				return
			}

			// 3. Extract Certificates (OBJ02)
			certs := extractCertsFromTL(tlData)

			tempMu.Lock()
			for _, cert := range certs {
				// Deduplicate using the string representation of the signature as a simple key
				key := string(cert.Signature)
				tempStore[key] = cert
			}
			tempMu.Unlock()
		}(url)
	}

	wg.Wait()

	// Safely update the live keystore
	s.mu.Lock()
	s.CertStore = tempStore
	s.mu.Unlock()

	slog.Info("Successfully loaded QTSP certificates into the local trust store", "number", len(tempStore))
}

func (s *TLService) fetchAndParseXML(url string) (*TrustServiceStatusList, error) {
	resp, err := s.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var tsl TrustServiceStatusList
	if err := xml.Unmarshal(body, &tsl); err != nil {
		return nil, fmt.Errorf("XML unmarshal failed: %w", err)
	}

	return &tsl, nil
}

func extractCertsFromTL(tsl *TrustServiceStatusList) []*x509.Certificate {
	var extracted []*x509.Certificate

	for _, tsp := range tsl.TSPList {
		for _, service := range tsp.Services {
			info := service.ServiceInformation

			// Filter by Service Status
			if info.ServiceStatus != ServiceStatusGranted {
				continue
			}

			// Filter by Service Type (Signature or Timestamp CA)
			if info.ServiceTypeIdentifier != ServiceTypeQCert && info.ServiceTypeIdentifier != ServiceTypeQTimestamp {
				continue
			}

			// Parse Digital Identities
			for _, identity := range info.DigitalIdentities {
				if identity.X509Certificate == "" {
					continue
				}

				certData, err := base64.StdEncoding.DecodeString(identity.X509Certificate)
				if err != nil {
					slog.Error("Failed to decode base64 certificate", "error", err)
					continue
				}

				cert, err := x509.ParseCertificate(certData)
				if err != nil {
					// Brainpool curves (e.g. brainpoolP256r1/P384r1/P512r1) used by some EU
					// QTSPs are not supported by Go's standard crypto/x509 package. These are
					// non-fatal — skip and continue loading other certificates.
					slog.Warn("Skipping certificate with unsupported algorithm (likely Brainpool curve)", "error", err)
					continue
				}

				extracted = append(extracted, cert)
			}
		}
	}
	return extracted
}

func main() {

	opts := &slog.HandlerOptions{
		AddSource: true,
	}

	// 2. Create the logger (Text or JSON)
	logger := slog.New(slog.NewTextHandler(os.Stdout, opts))

	// 3. Set it as the global default
	slog.SetDefault(logger)
	// Initialize the service
	service := NewTLService()

	// Start the periodic sync routine (e.g., every 24 hours)
	// For demonstration purposes, we run an initial sync immediately.
	service.executeSync()
	service.StartPeriodicSync(24 * time.Hour)

	// Keep main thread alive
	select {}
}
