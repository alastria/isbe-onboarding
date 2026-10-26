package tmfservice

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// recorder captures the method and path of every call the service makes, so a test can assert
// which TM Forum operations were issued and, just as importantly, which ones were not.
type recorder struct {
	calls []string
}

func (r *recorder) record(req *http.Request) {
	r.calls = append(r.calls, req.Method+" "+req.URL.Path)
}

func (r *recorder) count(method, pathPrefix string) int {
	n := 0
	for _, c := range r.calls {
		if strings.HasPrefix(c, method+" ") && strings.Contains(c, pathPrefix) {
			n++
		}
	}
	return n
}

func sampleCreate(name string) *Organization_Create {
	org := &Organization_Create{TradingName: name}
	org.Name = name
	return org
}

func TestUpsertPatchesAnExistingOrganization(t *testing.T) {
	rec := &recorder{}
	const existingID = "urn:ngsi-ld:organization:did:elsi:VATES-B12345678"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rec.record(req)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case req.Method == http.MethodGet:
			json.NewEncoder(w).Encode([]Organization{{ID: existingID}})
		case req.Method == http.MethodPatch:
			json.NewEncoder(w).Encode(Organization{ID: existingID})
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	svc := &TMFService{BaseURL: srv.URL, client: srv.Client()}
	if err := svc.TMFUpsertOrganizationByELSI("token", "VATES-B12345678", sampleCreate("Acme")); err != nil {
		t.Fatalf("upsert returned an error: %v", err)
	}

	if got := rec.count(http.MethodPatch, "/organization/"); got != 1 {
		t.Errorf("expected exactly one PATCH on the existing organization, got %d (calls: %v)", got, rec.calls)
	}
	if got := rec.count(http.MethodDelete, "/organization"); got != 0 {
		t.Errorf("the existing organization must never be deleted, got %d DELETE calls", got)
	}
	if got := rec.count(http.MethodPost, "/organization"); got != 0 {
		t.Errorf("an existing organization must not be recreated, got %d POST calls", got)
	}
}

func TestUpsertCreatesAMissingOrganization(t *testing.T) {
	rec := &recorder{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rec.record(req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode([]Organization{})
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(Organization{ID: "urn:ngsi-ld:organization:did:elsi:VATES-B99999999"})
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	svc := &TMFService{BaseURL: srv.URL, client: srv.Client()}
	if err := svc.TMFUpsertOrganizationByELSI("token", "VATES-B99999999", sampleCreate("Acme")); err != nil {
		t.Fatalf("upsert returned an error: %v", err)
	}

	if got := rec.count(http.MethodPost, "/organization"); got != 1 {
		t.Errorf("expected exactly one POST creating the organization, got %d (calls: %v)", got, rec.calls)
	}
	if got := rec.count(http.MethodPatch, "/organization"); got != 0 {
		t.Errorf("nothing to patch when the organization is missing, got %d PATCH calls", got)
	}
	if got := rec.count(http.MethodDelete, "/organization"); got != 0 {
		t.Errorf("no deletion must ever be issued, got %d DELETE calls", got)
	}
}

func TestUpsertReportsAFailedPatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]Organization{{ID: "urn:ngsi-ld:organization:did:elsi:VATES-B12345678"}})
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	svc := &TMFService{BaseURL: srv.URL, client: srv.Client()}
	if err := svc.TMFUpsertOrganizationByELSI("token", "VATES-B12345678", sampleCreate("Acme")); err == nil {
		t.Error("a rejected patch must surface as an error, got nil")
	}
}
