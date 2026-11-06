package tsaservice

import (
	"crypto/sha512"
	"io"
	"log/slog"
	"math/big"
	"testing"

	"github.com/alastria/isbe-onboarding/tsaservice/tsatest"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func bigOne() *big.Int { return big.NewInt(1) }

// mustRequest builds the parsed form of a SHA-512 request for data, without nonce.
func mustRequest(t testing.TB, data []byte) *tsatest.Request {
	t.Helper()
	d := sha512.Sum512(data)
	return &tsatest.Request{HashOID: oidSHA512, Digest: d[:], CertReq: true}
}
