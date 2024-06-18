package certificate

import "crypto/x509"

type Supplier interface {
	Name() string
	Certificates() []*x509.Certificate
}
