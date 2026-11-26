package tsaservice

import (
	"crypto/rand"
	"encoding/asn1"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// nonceBits is the size of the request nonce. 64 bits is what OpenSSL and most
// TSAs use; it makes accidental repetition negligible while staying within the
// limits that some TSA implementations impose on the nonce.
const nonceBits = 64

// newNonce returns a uniformly random positive nonce.
func newNonce() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), nonceBits)
	for {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// buildTimeStampReq encodes a DER TimeStampReq (RFC 3161 section 2.4.1).
// certReq is always true: the verifier needs the TSA certificate in the token.
func buildTimeStampReq(alg hashAlgorithm, digest []byte, nonce *big.Int, policy asn1.ObjectIdentifier) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(alg.oid)
				b.AddASN1NULL()
			})
			b.AddASN1OctetString(digest)
		})
		if policy != nil {
			b.AddASN1ObjectIdentifier(policy)
		}
		if nonce != nil {
			b.AddASN1BigInt(nonce)
		}
		b.AddASN1Boolean(true)
	})
	return b.Bytes()
}
