// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package finalizers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"net/http"
	"strings"
	"time"

	"github.com/ccoveille/go-safecast/v2"
	"github.com/dadrus/httpsig"
	"github.com/inhies/go-bytesize"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/keyregistry"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/pkix"
)

const (
	defaultHTTPMessageSignaturesTTL         = time.Minute
	defaultHTTPMessageSignaturesMaxBodySize = bytesize.MB
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registry.Register(
		types.KindFinalizer,
		FinalizerHTTPMessageSignatures,
		registry.FactoryFunc(newHTTPMessageSignaturesFinalizer),
	)
}

type httpMessageSignaturesFinalizerConfig struct {
	Signer      SignerConfig       `mapstructure:"signer"        validate:"required"`
	Components  []string           `mapstructure:"components"    validate:"gt=0,dive,required"`
	TTL         *time.Duration     `mapstructure:"ttl"           validate:"omitempty,gt=0"`
	Label       string             `mapstructure:"label"`
	MaxBodySize *bytesize.ByteSize `mapstructure:"max_body_size" validate:"omitempty,gt=0"`
}

type httpMessageSignaturesFinalizer struct {
	name        string
	id          string
	app         app.Context
	signer      *httpMessageSignaturesSigner
	components  []string
	ttl         time.Duration
	label       string
	maxBodySize bytesize.ByteSize
}

func newHTTPMessageSignaturesFinalizer(
	app app.Context,
	name string,
	rawConfig map[string]any,
) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", FinalizerHTTPMessageSignatures).
		Str("_name", name).
		Msg("Creating finalizer")

	conf, err := decodeHTTPMessageSignaturesFinalizerConfig(app, name, rawConfig)
	if err != nil {
		return nil, err
	}

	signer, err := newHTTPMessageSignaturesSigner(
		&conf.Signer,
		app.SecretResolver(),
		app.KeyRegistry(),
	)
	if err != nil {
		return nil, err
	}

	return newHTTPMessageSignaturesFinalizerFromConfig(app, name, name, conf, signer), nil
}

func decodeHTTPMessageSignaturesFinalizerConfig(
	app app.Context,
	name string,
	rawConfig map[string]any,
) (*httpMessageSignaturesFinalizerConfig, error) {
	var conf httpMessageSignaturesFinalizerConfig
	if err := decodeConfig(app, rawConfig, &conf,
		template.WithName("finalizer."+FinalizerHTTPMessageSignatures+"."+name),
		template.WithSecretResolver(app.SecretResolver()),
	); err != nil {
		return nil, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"failed decoding config for %s finalizer '%s'", FinalizerHTTPMessageSignatures, name,
		).CausedBy(err)
	}

	if err := validateHTTPMessageSignatureComponents(conf.Components); err != nil {
		return nil, err
	}

	return &conf, nil
}

func validateHTTPMessageSignatureComponents(components []string) error {
	for _, component := range components {
		if strings.EqualFold(httpMessageSignatureComponentIdentifier(component), "host") {
			return errorchain.NewWithMessage(
				pipeline.ErrConfiguration,
				"http message signatures finalizer requires @authority instead of host in components",
			)
		}
	}

	return nil
}

func httpMessageSignatureComponentIdentifier(component string) string {
	identifier, _, _ := strings.Cut(component, ";")

	return strings.TrimSpace(identifier)
}

func newHTTPMessageSignaturesFinalizerFromConfig(
	app app.Context,
	name, id string,
	conf *httpMessageSignaturesFinalizerConfig,
	signer *httpMessageSignaturesSigner,
) *httpMessageSignaturesFinalizer {
	return &httpMessageSignaturesFinalizer{
		name:       name,
		id:         id,
		app:        app,
		signer:     signer,
		components: conf.Components,
		ttl: x.IfThenElseExec(conf.TTL != nil,
			func() time.Duration { return *conf.TTL },
			func() time.Duration { return defaultHTTPMessageSignaturesTTL }),
		label: x.IfThenElseExec(len(conf.Label) != 0,
			func() string { return conf.Label },
			func() string { return "sig" }),
		maxBodySize: x.IfThenElseExec(conf.MaxBodySize != nil,
			func() bytesize.ByteSize { return *conf.MaxBodySize },
			func() bytesize.ByteSize { return defaultHTTPMessageSignaturesMaxBodySize }),
	}
}

func (f *httpMessageSignaturesFinalizer) Execute(ctx pipeline.Context, _ pipeline.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", FinalizerHTTPMessageSignatures).
		Str("_name", f.name).
		Str("_id", f.id).
		Msg("Executing finalizer")

	registry, ok := ctx.(pipeline.HTTPMessageFinalizerRegistry)
	if !ok {
		return errorchain.NewWithMessage(
			pipeline.ErrInternal,
			"request context does not support http message finalization",
		).WithAspects(f)
	}

	registry.AddHTTPMessageFinalizerForUpstream(
		pipeline.NewHTTPMessageFinalizer(
			safecast.MustConvert[int64](uint64(f.maxBodySize)),
			f.sign,
		),
	)

	return nil
}

func (f *httpMessageSignaturesFinalizer) CreateStep(
	resolver secrets.Resolver,
	def types.StepDefinition,
) (pipeline.Step, error) {
	if def.IsEmpty() {
		return f, nil
	}

	if len(def.Config) == 0 {
		fin := *f
		fin.id = x.IfThenElse(len(def.ID) == 0, f.id, def.ID)

		return &fin, nil
	}

	type Config struct {
		Signer      *SignerConfig      `mapstructure:"signer"        validate:"not_allowed"`
		Components  []string           `mapstructure:"components"    validate:"omitempty,dive,required"`
		TTL         *time.Duration     `mapstructure:"ttl"           validate:"omitempty,gt=0"`
		Label       string             `mapstructure:"label"`
		MaxBodySize *bytesize.ByteSize `mapstructure:"max_body_size" validate:"omitempty,gt=0"`
	}

	var conf Config
	if err := decodeConfig(f.app, def.Config, &conf,
		template.WithName("finalizer."+FinalizerHTTPMessageSignatures+"."+f.name),
		template.WithSecretResolver(resolver),
	); err != nil {
		return nil, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"failed decoding config for %s finalizer '%s'", FinalizerHTTPMessageSignatures, f.name,
		).CausedBy(err)
	}

	if len(conf.Components) != 0 {
		if err := validateHTTPMessageSignatureComponents(conf.Components); err != nil {
			return nil, err
		}
	}

	return &httpMessageSignaturesFinalizer{
		name:   f.name,
		id:     x.IfThenElse(len(def.ID) == 0, f.id, def.ID),
		app:    f.app,
		signer: f.signer,
		components: x.IfThenElseExec(len(conf.Components) != 0,
			func() []string { return conf.Components },
			func() []string { return f.components }),
		ttl: x.IfThenElseExec(conf.TTL != nil,
			func() time.Duration { return *conf.TTL },
			func() time.Duration { return f.ttl }),
		label: x.IfThenElseExec(len(conf.Label) != 0,
			func() string { return conf.Label },
			func() string { return f.label }),
		maxBodySize: x.IfThenElseExec(conf.MaxBodySize != nil,
			func() bytesize.ByteSize { return *conf.MaxBodySize },
			func() bytesize.ByteSize { return f.maxBodySize }),
	}, nil
}

func (f *httpMessageSignaturesFinalizer) Name() string            { return f.name }
func (f *httpMessageSignaturesFinalizer) ID() string              { return f.id }
func (f *httpMessageSignaturesFinalizer) Type() string            { return f.name }
func (*httpMessageSignaturesFinalizer) Accept(_ pipeline.Visitor) {}
func (*httpMessageSignaturesFinalizer) Kind() types.Kind          { return types.KindFinalizer }

func (f *httpMessageSignaturesFinalizer) sign(msg *pipeline.HTTPMessage) (http.Header, error) {
	header, err := f.signer.Sign(msg, f.components, f.ttl, f.label, f.maxBodySize)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrInternal,
			"failed signing http message",
		).WithAspects(f).CausedBy(err)
	}

	return header, nil
}

type httpMessageSignaturesSigner struct {
	tag      string
	ref      secrets.Reference
	informer *secrets.SecretInformer[httpsig.Key]
	ko       keyregistry.KeyObserver
}

func newHTTPMessageSignaturesSigner(
	conf *SignerConfig,
	resolver secrets.Resolver,
	ko keyregistry.KeyObserver,
) (*httpMessageSignaturesSigner, error) {
	signer := &httpMessageSignaturesSigner{
		tag: x.IfThenElse(len(conf.Name) == 0, "heimdall", conf.Name),
		ref: secrets.Reference{
			Source:   conf.Secret.Source,
			Selector: conf.Secret.Selector,
		},
		ko: ko,
	}

	var err error

	signer.informer, err = secrets.NewSecretInformer(
		resolver,
		signer.ref,
		secrets.WithConverter(toHTTPSigSigningKey),
		secrets.WithUpdateCallback(signer.onSecretUpdated),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed creating secret informer for http message signing material",
		).CausedBy(err)
	}

	return signer, nil
}

func (s *httpMessageSignaturesSigner) Sign(
	msg *pipeline.HTTPMessage,
	components []string,
	ttl time.Duration,
	label string,
	maxBodySize bytesize.ByteSize,
) (http.Header, error) {
	key, ok := s.informer.Get()
	if !ok {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"http message signing material is not available",
		)
	}

	signer, err := httpsig.NewSigner(
		key,
		httpsig.WithComponents(components...),
		httpsig.WithTTL(ttl),
		httpsig.WithLabel(label),
		httpsig.WithTag(s.tag),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed creating http message signer",
		).CausedBy(err)
	}

	return signer.Sign(&httpsig.Message{
		Context:   msg.Context,
		Method:    msg.Method,
		Authority: msg.Authority,
		URL:       msg.URL,
		Header:    msg.Header.Clone(),
		Body: pipeline.HTTPMessageBodyWithMaxSize(
			msg.Body,
			safecast.MustConvert[int64](uint64(maxBodySize)),
		),
		IsRequest: true,
	})
}

func (s *httpMessageSignaturesSigner) onSecretUpdated(_ context.Context, secret secrets.Secret, _ httpsig.Key) error {
	if _, ok := secret.(secrets.AsymmetricKeySecret); ok && s.ko != nil {
		s.ko.Notify(s.ref)
	}

	return nil
}

func toHTTPSigSigningKey(secret secrets.Secret) (httpsig.Key, error) {
	switch key := secret.(type) {
	case secrets.AsymmetricKeySecret:
		return asymmetricSecretToHTTPSigSigningKey(key)
	case secrets.SymmetricKeySecret:
		return symmetricSecretToHTTPSigSigningKey(key)
	default:
		return httpsig.Key{}, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"resolved secret '%s' is not suitable for http message signing",
			secret.Selector(),
		)
	}
}

func asymmetricSecretToHTTPSigSigningKey(secret secrets.AsymmetricKeySecret) (httpsig.Key, error) {
	privateKey := secret.PrivateKey()
	if privateKey == nil {
		return httpsig.Key{}, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"resolved asymmetric secret '%s' does not contain private key material",
			secret.Selector(),
		)
	}

	if err := validateHTTPMessageSigningCertificate(secret); err != nil {
		return httpsig.Key{}, err
	}

	alg, err := signingAlgorithm(privateKey.Public())
	if err != nil {
		return httpsig.Key{}, err
	}

	return httpsig.Key{
		KeyID:     secret.KeyID(),
		Algorithm: alg,
		Key:       privateKey,
	}, nil
}

func symmetricSecretToHTTPSigSigningKey(secret secrets.SymmetricKeySecret) (httpsig.Key, error) {
	alg, err := hmacSigningAlgorithm(secret.Algorithm())
	if err != nil {
		return httpsig.Key{}, err
	}

	return httpsig.Key{
		KeyID:     secret.KeyID(),
		Algorithm: alg,
		Key:       secret.Key(),
	}, nil
}

func signingAlgorithm(publicKey crypto.PublicKey) (httpsig.SignatureAlgorithm, error) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return rsaSigningAlgorithm(key.Size() * 8) //nolint:mnd
	case *ecdsa.PublicKey:
		return ecdsaSigningAlgorithm(key.Params().BitSize)
	case ed25519.PublicKey:
		return httpsig.Ed25519, nil
	default:
		return "", errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"unsupported http message signing key type: %T",
			publicKey,
		)
	}
}

func rsaSigningAlgorithm(keySize int) (httpsig.SignatureAlgorithm, error) {
	switch keySize {
	case 2048: //nolint:mnd
		return httpsig.RsaPssSha256, nil
	case 3072: //nolint:mnd
		return httpsig.RsaPssSha384, nil
	case 4096: //nolint:mnd
		return httpsig.RsaPssSha512, nil
	default:
		return "", errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"unsupported RSA key size for http message signing: %d",
			keySize,
		)
	}
}

func ecdsaSigningAlgorithm(keySize int) (httpsig.SignatureAlgorithm, error) {
	switch keySize {
	case 256: //nolint:mnd
		return httpsig.EcdsaP256Sha256, nil
	case 384: //nolint:mnd
		return httpsig.EcdsaP384Sha384, nil
	case 521: //nolint:mnd
		return httpsig.EcdsaP521Sha512, nil
	default:
		return "", errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"unsupported ECDSA key size for http message signing: %d",
			keySize,
		)
	}
}

func hmacSigningAlgorithm(alg string) (httpsig.SignatureAlgorithm, error) {
	switch alg {
	case string(httpsig.HmacSha256), "HS256":
		return httpsig.HmacSha256, nil
	case string(httpsig.HmacSha384), "HS384":
		return httpsig.HmacSha384, nil
	case string(httpsig.HmacSha512), "HS512":
		return httpsig.HmacSha512, nil
	default:
		return "", errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"unsupported HMAC algorithm for http message signing: %s",
			alg,
		)
	}
}

func validateHTTPMessageSigningCertificate(secret secrets.AsymmetricKeySecret) error {
	chain := secret.CertChain()
	if len(chain) == 0 {
		return nil
	}

	opts := []pkix.ValidationOption{
		pkix.WithKeyUsage(x509.KeyUsageDigitalSignature), //nolint:gosec
		pkix.WithRootCACertificates([]*x509.Certificate{chain[len(chain)-1]}),
		pkix.WithCurrentTime(time.Now()),
	}

	if len(chain) > 2 { //nolint:mnd
		opts = append(opts, pkix.WithIntermediateCACertificates(chain[1:len(chain)-1]))
	}

	if err := pkix.ValidateCertificate(chain[0], opts...); err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"configured certificate cannot be used for http message signing purposes",
		).CausedBy(err)
	}

	return nil
}
