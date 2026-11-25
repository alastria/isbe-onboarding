// Package certpolicytest builds throw-away PKIs for tests: a root CA, an intermediate CA,
// client certificates and CRLs served over HTTP. Keys are generated in memory for each
// test run; nothing is written to disk and nothing is meant for real use.
package certpolicytest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// OIDs of the Subject attributes that matter to the onboarding.
var (
	OIDOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
	OIDSerialNumber           = asn1.ObjectIdentifier{2, 5, 4, 5}
)

// CA is a certificate authority of the test PKI.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer

	pki     *PKI
	name    string
	mu      sync.Mutex
	revoked []x509.RevocationListEntry
	// CRLMode controls what the CRL endpoint of this CA returns.
	CRLMode CRLMode
}

// CRLMode selects the behaviour of a CA's CRL endpoint.
type CRLMode int

const (
	CRLValid       CRLMode = iota // a current CRL signed by the CA
	CRLUnavailable                // HTTP 503
	CRLStale                      // a CRL whose nextUpdate is in the past
	CRLBadSig                     // a CRL signed by another key
	CRLGarbage                    // bytes that are not a CRL
	CRLRedirect                   // a redirect to the CRL (redirects must not be followed)
)

// PKI is a root and an intermediate CA, plus an HTTP server for their CRLs.
type PKI struct {
	t      testing.TB
	Now    time.Time
	Server *httptest.Server

	Root         *CA
	Intermediate *CA

	mu  sync.Mutex
	cas map[string]*CA
}

// New creates a PKI whose clock is now. The HTTP server is closed when the test ends.
func New(t testing.TB, name string) *PKI {
	t.Helper()
	p := &PKI{t: t, Now: time.Now(), cas: map[string]*CA{}}
	p.Server = httptest.NewServer(http.HandlerFunc(p.serveCRL))
	t.Cleanup(p.Server.Close)

	p.Root = p.newCA(name+"-root", nil)
	p.Intermediate = p.newCA(name+"-intermediate", p.Root)
	return p
}

func (p *PKI) crlURL(caName string) string { return p.Server.URL + "/crl/" + caName + ".crl" }

func (p *PKI) newCA(name string, parent *CA) *CA {
	p.t.Helper()
	key := mustRSA(p.t, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(p.t),
		Subject:               pkix.Name{CommonName: name + " - TEST ONLY", Organization: []string{"ISBE TEST PKI"}, Country: []string{"ES"}},
		NotBefore:             p.Now.Add(-48 * time.Hour),
		NotAfter:              p.Now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	signer, parentCert := crypto.Signer(key), tmpl
	if parent != nil {
		signer, parentCert = parent.Key, parent.Cert
		tmpl.CRLDistributionPoints = []string{p.crlURL(parent.name)}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, signer)
	if err != nil {
		p.t.Fatalf("creating CA %s: %v", name, err)
	}
	cert, _ := x509.ParseCertificate(der)
	ca := &CA{Cert: cert, Key: key, pki: p, name: name}
	p.mu.Lock()
	p.cas[name] = ca
	p.mu.Unlock()
	return ca
}

// LeafOptions describe a client certificate. The zero value plus a Subject gives a
// certificate with the same technical profile as the target non-eIDAS organizational
// certificate: RSA 2048, SHA256withRSA, KU digitalSignature, EKU clientAuth, CRL DP.
type LeafOptions struct {
	Subject           pkix.Name
	NotBefore         time.Time // default: now - 24h
	NotAfter          time.Time // default: now + 365d
	KeyUsage          x509.KeyUsage
	NoKeyUsage        bool
	ExtKeyUsage       []x509.ExtKeyUsage // default: clientAuth
	NoExtKeyUsage     bool
	IsCA              bool
	RSABits           int // default 2048
	ECDSA             bool
	NoCRLDP           bool
	CRLDistributionPt []string // overrides the default CRL DP
	Key               crypto.Signer
}

// Leaf is a client certificate with its key.
type Leaf struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// B64DER returns the certificate as the reverse proxy sends it: base64 of the DER.
func (l *Leaf) B64DER() string { return base64.StdEncoding.EncodeToString(l.Cert.Raw) }

// Issue creates a client certificate signed by this CA.
func (ca *CA) Issue(opts LeafOptions) *Leaf {
	t := ca.pki.t
	t.Helper()
	var key crypto.Signer
	switch {
	case opts.Key != nil:
		key = opts.Key
	case opts.ECDSA:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	default:
		bits := opts.RSABits
		if bits == 0 {
			bits = 2048
		}
		key = mustRSA(t, bits)
	}
	if opts.NotBefore.IsZero() {
		opts.NotBefore = ca.pki.Now.Add(-24 * time.Hour)
	}
	if opts.NotAfter.IsZero() {
		opts.NotAfter = ca.pki.Now.Add(365 * 24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               opts.Subject,
		NotBefore:             opts.NotBefore,
		NotAfter:              opts.NotAfter,
		BasicConstraintsValid: true,
		IsCA:                  opts.IsCA,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	if !opts.NoKeyUsage {
		tmpl.KeyUsage = opts.KeyUsage
		if tmpl.KeyUsage == 0 {
			tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		}
	}
	if !opts.NoExtKeyUsage {
		tmpl.ExtKeyUsage = opts.ExtKeyUsage
		if tmpl.ExtKeyUsage == nil {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
	}
	if !opts.NoCRLDP {
		tmpl.CRLDistributionPoints = opts.CRLDistributionPt
		if tmpl.CRLDistributionPoints == nil {
			tmpl.CRLDistributionPoints = []string{ca.pki.crlURL(ca.name)}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		t.Fatalf("issuing certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Leaf{Cert: cert, Key: key}
}

// Revoke adds the certificate to the CA's CRL.
func (ca *CA) Revoke(cert *x509.Certificate) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.revoked = append(ca.revoked, x509.RevocationListEntry{
		SerialNumber:   cert.SerialNumber,
		RevocationTime: ca.pki.Now.Add(-time.Hour),
		ReasonCode:     1, // keyCompromise
	})
}

func (p *PKI) serveCRL(w http.ResponseWriter, r *http.Request) {
	const prefix, suffix = "/crl/", ".crl"
	path := r.URL.Path
	if len(path) <= len(prefix)+len(suffix) {
		http.NotFound(w, r)
		return
	}
	name := path[len(prefix) : len(path)-len(suffix)]
	p.mu.Lock()
	ca := p.cas[name]
	p.mu.Unlock()
	if ca == nil {
		http.NotFound(w, r)
		return
	}
	ca.mu.Lock()
	mode, revoked := ca.CRLMode, append([]x509.RevocationListEntry(nil), ca.revoked...)
	ca.mu.Unlock()

	if mode == CRLRedirect && r.URL.Query().Get("redirected") == "" {
		http.Redirect(w, r, path+"?redirected=1", http.StatusFound)
		return
	}

	thisUpdate, nextUpdate := p.Now.Add(-time.Hour), p.Now.Add(24*time.Hour)
	signer := ca.Key
	switch mode {
	case CRLUnavailable:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	case CRLGarbage:
		_, _ = w.Write([]byte("this is not a CRL"))
		return
	case CRLStale:
		thisUpdate, nextUpdate = p.Now.Add(-72*time.Hour), p.Now.Add(-48*time.Hour)
	case CRLBadSig:
		signer = mustRSA(p.t, 2048)
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(time.Now().UnixNano()),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: revoked,
	}, ca.Cert, signer)
	if err != nil {
		// CreateRevocationList checks that the key matches the issuer; for the bad
		// signature case sign with a self-made issuer of the same name instead.
		fake := *ca.Cert
		fake.PublicKey = signer.Public()
		fake.SubjectKeyId = nil
		der, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number: big.NewInt(1), ThisUpdate: thisUpdate, NextUpdate: nextUpdate,
			RevokedCertificateEntries: revoked,
		}, &fake, signer)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	_, _ = w.Write(der)
}

// NewIntermediate creates another intermediate CA under the root.
func (p *PKI) NewIntermediate(name string) *CA { return p.newCA(name, p.Root) }

// Name builds a Subject with the given attributes plus optional extra ones.
func Name(cn, o, c, l string, extra ...pkix.AttributeTypeAndValue) pkix.Name {
	n := pkix.Name{CommonName: cn, Country: []string{c}, Locality: []string{l}, ExtraNames: extra}
	if o != "" {
		n.Organization = []string{o}
	}
	return n
}

// OrganizationIdentifier returns the organizationIdentifier attribute (OID 2.5.4.97).
func OrganizationIdentifier(v string) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{Type: OIDOrganizationIdentifier, Value: v}
}

// SubjectSerialNumber returns the Subject serialNumber attribute (OID 2.5.4.5), which is
// not the X.509 certificate serial number.
func SubjectSerialNumber(v string) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{Type: OIDSerialNumber, Value: v}
}

func mustRSA(t testing.TB, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func randomSerial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		t.Fatal(err)
	}
	return n.Add(n, big.NewInt(1))
}
