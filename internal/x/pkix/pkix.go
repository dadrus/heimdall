package pkix

import (
	"crypto/sha1" // nolint: gosec
	"crypto/x509"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func SubjectKeyID(pubKey any) ([]byte, error) {
	// Subject Key Identifier support
	// https://www.ietf.org/rfc/rfc3280.txt (section 4.2.1.2)
	marshaledKey, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to calculated subject public key id").CausedBy(err)
	}

	subjKeyID := sha1.Sum(marshaledKey) // nolint: gosec

	return subjKeyID[:], nil
}
