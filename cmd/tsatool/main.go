// Command tsatool helps operators diagnose the TSA integration.
//
//	tsatool verify-registration -db data/onboard.db -org VATES-B12345678
//	    Rebuilds the timestamped evidence of a registration (contract PDF +
//	    certificate) and verifies the stored token. Read-only, no network
//	    access to the TSA, no credentials needed.
//
//	tsatool verify -tsr token.tsr -data evidence.bin
//	tsatool verify -tsr token.tsr -contract contract.pdf -cert cert.b64
//	    Verifies a token file against the data, or against a contract and
//	    certificate combined in the registration evidence format.
//
//	tsatool probe -confirm
//	    Requests ONE real timestamp for random data using the TSA_* environment
//	    variables and verifies it. It consumes provider quota and must only be
//	    run deliberately (e.g. after rotating credentials).
//
// Trust settings (TSA_TRUST_ANCHORS_FILE, TSA_TRUST_ANCHOR_SHA256,
// TSA_INTERMEDIATES_FILE, TSA_POLICY_OID, ...) are read from the environment,
// exactly like the server does.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/alastria/isbe-onboarding/database"
	"github.com/alastria/isbe-onboarding/tsaservice"
	"github.com/alastria/isbe-onboarding/types"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	var err error
	switch os.Args[1] {
	case "verify":
		err = verify(os.Args[2:])
	case "verify-registration":
		err = verifyRegistration(os.Args[2:])
	case "probe":
		err = probe(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAILED:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tsatool verify|verify-registration|probe [flags]  (see go doc ./cmd/tsatool)")
	os.Exit(2)
}

func configFromEnv() (*tsaservice.TSAConfig, error) {
	cfg := &tsaservice.TSAConfig{Environment: os.Getenv("PROFILE")}
	if err := tsaservice.ApplyEnv(cfg, os.Getenv, os.ReadFile); err != nil {
		return nil, err
	}
	return cfg, nil
}

func newVerifier() (*tsaservice.Verifier, error) {
	cfg, err := configFromEnv()
	if err != nil {
		return nil, err
	}
	return tsaservice.NewVerifier(context.Background(), cfg)
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	tsrPath := fs.String("tsr", "", "DER TimeStampResp file")
	dataPath := fs.String("data", "", "file with the exact timestamped data")
	contractPath := fs.String("contract", "", "contract PDF (registration evidence format)")
	certPath := fs.String("cert", "", "file with the eidas_cert value (registration evidence format)")
	_ = fs.Parse(args)

	if *tsrPath == "" || (*dataPath == "") == (*contractPath == "") {
		return fmt.Errorf("use -tsr with either -data or -contract and -cert")
	}
	tsr, err := os.ReadFile(*tsrPath)
	if err != nil {
		return err
	}
	var data []byte
	if *dataPath != "" {
		if data, err = os.ReadFile(*dataPath); err != nil {
			return err
		}
	} else {
		contract, err := os.ReadFile(*contractPath)
		if err != nil {
			return err
		}
		cert, err := os.ReadFile(*certPath)
		if err != nil {
			return err
		}
		data = database.TimestampedEvidence(contract, string(cert))
	}

	v, err := newVerifier()
	if err != nil {
		return err
	}
	vt, err := v.Verify(tsr, data)
	if err != nil {
		return err
	}
	report(vt)
	return nil
}

func verifyRegistration(args []string) error {
	fs := flag.NewFlagSet("verify-registration", flag.ExitOnError)
	dbPath := fs.String("db", "data/onboard.db", "SQLite database (opened read-only)")
	org := fs.String("org", "", "organization_identifier of the registration")
	_ = fs.Parse(args)
	if *org == "" {
		return fmt.Errorf("-org is required")
	}
	if _, err := os.Stat(*dbPath); err != nil {
		return err
	}
	db, err := database.OpenReadOnly(*dbPath, types.ProfileFromString(os.Getenv("PROFILE")))
	if err != nil {
		return err
	}
	defer db.Close()

	v, err := newVerifier()
	if err != nil {
		return err
	}
	vt, err := db.VerifyRegistrationEvidence(v, *org)
	if err != nil {
		return err
	}
	report(vt)
	return nil
}

func probe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	confirm := fs.Bool("confirm", false, "required: acknowledges that one billable timestamp will be requested")
	_ = fs.Parse(args)
	if !*confirm {
		return fmt.Errorf("probe requests a real, possibly billable, timestamp; re-run with -confirm")
	}
	cfg, err := configFromEnv()
	if err != nil {
		return err
	}
	s, err := tsaservice.NewTSAService(cfg)
	if err != nil {
		return err
	}
	data := make([]byte, 32)
	_, _ = rand.Read(data)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tok, err := s.Timestamp(tsaservice.WithCorrelationID(ctx, "tsatool-probe"), data)
	if err != nil {
		return err
	}
	report(tok.VerifiedToken)
	return nil
}

func report(vt *tsaservice.VerifiedToken) {
	fmt.Println("OK: timestamp token verified")
	fmt.Println("  genTime:       ", vt.GenTime.Format(time.RFC3339Nano))
	fmt.Println("  accuracy:      ", vt.Accuracy)
	fmt.Println("  serial:        ", vt.SerialNumber.Text(16))
	fmt.Println("  policy:        ", vt.Policy)
	fmt.Println("  hash:          ", vt.HashAlgorithm)
	fmt.Println("  signer:        ", vt.Signer.Subject.String())
	for i, c := range vt.Chain {
		fmt.Printf("  chain[%d]:      %s (sha256 %s)\n", i, c.Subject.CommonName, tsaservice.Fingerprint(c.Raw))
	}
	fmt.Println("  revocation:    ", map[bool]string{true: "checked", false: "not checked"}[vt.RevocationChecked])
	fmt.Println("Note: this proves a valid signature by a trusted TSA. eIDAS qualified status must be")
	fmt.Println("checked separately against the EU Trusted List for the signer at genTime.")
}
