package keystore_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"golang.org/x/exp/slices"

	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x"
)

type PEMBlockOption func(*pem.Block)

func WithPEMHeader(key, value string) PEMBlockOption {
	return func(block *pem.Block) {
		block.Headers[key] = value
	}
}

func WithX509Certificate(cert *x509.Certificate, opts ...PEMBlockOption) PEMEntryOption {
	return func(block *pem.Block) error {
		block.Type = "CERTIFICATE"
		block.Bytes = cert.Raw

		for _, opt := range opts {
			opt(block)
		}

		return nil
	}
}

func WithECDSAPublicKey(key *ecdsa.PublicKey, opts ...PEMBlockOption) PEMEntryOption {
	return func(block *pem.Block) error {
		raw, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return err
		}

		block.Type = "ECDSA PUBLIC KEY"
		block.Bytes = raw

		for _, opt := range opts {
			opt(block)
		}

		return nil
	}
}

func WithECDSAPrivateKey(key *ecdsa.PrivateKey, opts ...PEMBlockOption) PEMEntryOption {
	return func(block *pem.Block) error {
		raw, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}

		block.Type = "EC PRIVATE KEY"
		block.Bytes = raw

		for _, opt := range opts {
			opt(block)
		}

		return nil
	}
}

type PEMEntryOption func(*pem.Block) error

func BuildPEM(opts ...PEMEntryOption) ([]byte, error) {
	buf := new(bytes.Buffer)

	for _, opt := range opts {
		block := &pem.Block{Headers: make(map[string]string)}

		err := opt(block)
		if err != nil {
			return nil, err
		}

		if err = pem.Encode(buf, block); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

type CA struct {
	lastEECertSN int64
	priv         *ecdsa.PrivateKey
	cert         *x509.Certificate
}

func (ca *CA) NextSN() *big.Int {
	ca.lastEECertSN++

	return big.NewInt(ca.lastEECertSN)
}

func (ca *CA) IssueCertificate(opts ...CertificateBuilderOption) (*x509.Certificate, error) {
	options := slices.Clone(opts)
	options = append(options,
		WithSerialNumber(ca.NextSN()),
		WithIssuer(ca.priv, ca.cert),
	)

	cb := NewCertificateBuilder(options...)

	return cb.Build()
}

func NewCA(privKey *ecdsa.PrivateKey, cert *x509.Certificate) *CA {
	return &CA{
		lastEECertSN: 0,
		priv:         privKey,
		cert:         cert,
	}
}

func NewRootCA(CN string, validity time.Duration) (*CA, error) { // nolint: gocritic
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	opts := []CertificateBuilderOption{
		WithValidity(time.Now(), validity),
		WithSerialNumber(big.NewInt(1)),
		WithSubject(pkix.Name{
			CommonName:   CN,
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		WithSubjectPubKey(&priv.PublicKey, x509.ECDSAWithSHA384),
		WithIsCA(),
		WithSelfSigned(),
		WithSignaturePrivKey(priv),
	}

	cb := NewCertificateBuilder(opts...)

	cert, err := cb.Build()
	if err != nil {
		return nil, err
	}

	return &CA{
		priv:         priv,
		cert:         cert,
		lastEECertSN: 0,
	}, nil
}

type CertificateBuilderOption func(*CertificateBuilder)

type CertificateBuilder struct {
	tmpl                  *x509.Certificate
	subjectPubKey         any
	selfSigned            bool
	privKey               any
	issuerCert            *x509.Certificate
	generateKeyIdentifier bool
}

func WithValidity(notBefore time.Time, duration time.Duration) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.NotBefore = notBefore
		builder.tmpl.NotAfter = notBefore.Add(duration)
	}
}

func WithSerialNumber(SN *big.Int) CertificateBuilderOption { // nolint: gocritic
	return func(builder *CertificateBuilder) {
		builder.tmpl.SerialNumber = SN
	}
}

func WithSubject(name pkix.Name) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.Subject = name
	}
}

func WithKeyUsage(keyUsage x509.KeyUsage) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.KeyUsage = keyUsage
	}
}

func WithSubjectPubKey(key any, alg x509.SignatureAlgorithm) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.SignatureAlgorithm = alg
		builder.subjectPubKey = key
	}
}

func WithSelfSigned() CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.selfSigned = true
	}
}

func WithExtension(extension pkix.Extension) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.Extensions = append(builder.tmpl.Extensions, extension)
	}
}

func WithExtraExtension(extension pkix.Extension) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.ExtraExtensions = append(builder.tmpl.ExtraExtensions, extension)
	}
}

func WithIsCA() CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.IsCA = true
		builder.tmpl.BasicConstraintsValid = true
	}
}

func WithSignaturePrivKey(key any) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.privKey = key
	}
}

func WithIssuer(key any, cert *x509.Certificate) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.privKey = key
		builder.issuerCert = cert
	}
}

func WithSubjectKeyID(skid []byte) CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.tmpl.SubjectKeyId = skid
	}
}

func WithGeneratedSubjectKeyID() CertificateBuilderOption {
	return func(builder *CertificateBuilder) {
		builder.generateKeyIdentifier = true
	}
}

func NewCertificateBuilder(opts ...CertificateBuilderOption) *CertificateBuilder {
	builder := &CertificateBuilder{
		tmpl: &x509.Certificate{},
	}

	for _, opt := range opts {
		opt(builder)
	}

	if builder.tmpl.IsCA {
		builder.tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	return builder
}

func (cb *CertificateBuilder) Build() (*x509.Certificate, error) {
	var err error

	// generate public key identifier
	if cb.generateKeyIdentifier {
		if cb.tmpl.SubjectKeyId, err = keystore.SubjectKeyID(cb.subjectPubKey); err != nil {
			return nil, err
		}
	}

	raw, err := x509.CreateCertificate(
		rand.Reader,
		cb.tmpl,
		x.IfThenElse(cb.selfSigned, cb.tmpl, cb.issuerCert),
		cb.subjectPubKey,
		cb.privKey,
	)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(raw)
}
