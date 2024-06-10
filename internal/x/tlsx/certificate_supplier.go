package tlsx

import "crypto/x509"

type certificateSupplier struct {
	name string
	ks   *keyStore
}

func (c *certificateSupplier) Name() string                      { return c.name }
func (c *certificateSupplier) Certificates() []*x509.Certificate { return c.ks.certificates() }
