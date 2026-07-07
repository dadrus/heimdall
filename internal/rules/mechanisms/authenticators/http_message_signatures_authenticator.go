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

package authenticators

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ccoveille/go-safecast/v2"
	"github.com/dadrus/httpsig"
	"github.com/goccy/go-json"
	"github.com/inhies/go-bytesize"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const (
	defaultHTTPMessageSignaturesMaxAge      = 30 * time.Second
	defaultHTTPMessageSignaturesMaxBodySize = 1 * bytesize.MB
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registry.Register(
		types.KindAuthenticator,
		AuthenticatorHTTPMessageSignatures,
		registry.FactoryFunc(newHTTPMessageSignaturesAuthenticator),
	)
}

type httpMessageSignaturesConfig struct {
	KeyStore                 config.Secret      `mapstructure:"key_store"                  validate:"required"`
	RequiredComponents       []string           `mapstructure:"required_components"        validate:"gt=0,dive,required"`
	Tag                      string             `mapstructure:"tag"`
	MaxAge                   *time.Duration     `mapstructure:"max_age"`
	AllowedTimeSkew          *time.Duration     `mapstructure:"allowed_time_skew"`
	MaxBodySize              *bytesize.ByteSize `mapstructure:"max_body_size"              validate:"omitempty,gt=0"`
	CreatedTimestampRequired *bool              `mapstructure:"created_timestamp_required"`
	ExpiresTimestampRequired *bool              `mapstructure:"expires_timestamp_required"`
	ValidateAllSignatures    *bool              `mapstructure:"validate_all_signatures"`
	PrincipalInfo            PrincipalInfo      `mapstructure:"principal"                  validate:"-"`
	ErrorSignaling           struct {
		Enabled *bool `mapstructure:"enabled"`
	} `mapstructure:"error_signaling"`
}

type httpMessageSignaturesAuthenticator struct {
	name                     string
	id                       string
	principalName            string
	app                      app.Context
	keyStore                 config.Secret
	requiredComponents       []string
	tag                      string
	maxAge                   time.Duration
	allowedTimeSkew          time.Duration
	maxBodySize              bytesize.ByteSize
	createdTimestampRequired *bool
	expiresTimestampRequired *bool
	validateAllSignatures    bool
	sf                       PrincipalFactory
	errorSignalingEnabled    bool
	informer                 *secrets.SecretSetInformer[[]httpsig.Key]
}

func newHTTPMessageSignaturesAuthenticator(
	app app.Context,
	name string,
	rawConfig map[string]any,
) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", AuthenticatorHTTPMessageSignatures).
		Str("_name", name).
		Msg("Creating authenticator")

	conf, err := decodeHTTPMessageSignaturesConfig(app, name, rawConfig)
	if err != nil {
		return nil, err
	}

	informer, err := newHTTPMessageSignaturesKeyInformer(app.SecretResolver(), conf.KeyStore)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed creating http message signatures key informer",
		).CausedBy(err)
	}

	return newHTTPMessageSignaturesAuthenticatorFromConfig(app, name, name, DefaultPrincipalName, conf, informer), nil
}

func decodeHTTPMessageSignaturesConfig(
	app app.Context,
	name string,
	rawConfig map[string]any,
) (*httpMessageSignaturesConfig, error) {
	var conf httpMessageSignaturesConfig
	if err := decodeConfig(app, rawConfig, &conf,
		template.WithName("authenticator."+AuthenticatorHTTPMessageSignatures+"."+name),
		template.WithSecretResolver(app.SecretResolver()),
	); err != nil {
		return nil, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"failed decoding config for %s authenticator '%s'", AuthenticatorHTTPMessageSignatures, name,
		).CausedBy(err)
	}

	if len(conf.PrincipalInfo.IDFrom) == 0 {
		conf.PrincipalInfo.IDFrom = "key_id"
	}

	if conf.ValidateAllSignatures != nil && !*conf.ValidateAllSignatures && len(conf.Tag) == 0 {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"http message signatures authenticator requires a tag when validate_all_signatures is disabled",
		)
	}

	for _, component := range conf.RequiredComponents {
		if strings.EqualFold(httpMessageSignatureComponentIdentifier(component), "host") {
			return nil, errorchain.NewWithMessage(
				pipeline.ErrConfiguration,
				"http message signatures authenticator requires @authority instead of host in required_components",
			)
		}
	}

	return &conf, nil
}

func httpMessageSignatureComponentIdentifier(component string) string {
	identifier, _, _ := strings.Cut(component, ";")

	return strings.TrimSpace(identifier)
}

func newHTTPMessageSignaturesAuthenticatorFromConfig(
	app app.Context,
	name, id, principalName string,
	conf *httpMessageSignaturesConfig,
	informer *secrets.SecretSetInformer[[]httpsig.Key],
) *httpMessageSignaturesAuthenticator {
	return &httpMessageSignaturesAuthenticator{
		name:               name,
		id:                 id,
		principalName:      principalName,
		app:                app,
		keyStore:           conf.KeyStore,
		requiredComponents: conf.RequiredComponents,
		tag:                conf.Tag,
		maxAge: x.IfThenElseExec(
			conf.MaxAge != nil,
			func() time.Duration { return *conf.MaxAge },
			func() time.Duration { return defaultHTTPMessageSignaturesMaxAge },
		),
		allowedTimeSkew: x.IfThenElseExec(
			conf.AllowedTimeSkew != nil,
			func() time.Duration { return *conf.AllowedTimeSkew },
			func() time.Duration { return 0 },
		),
		maxBodySize: x.IfThenElseExec(
			conf.MaxBodySize != nil,
			func() bytesize.ByteSize { return *conf.MaxBodySize },
			func() bytesize.ByteSize { return defaultHTTPMessageSignaturesMaxBodySize },
		),
		createdTimestampRequired: conf.CreatedTimestampRequired,
		expiresTimestampRequired: conf.ExpiresTimestampRequired,
		validateAllSignatures: x.IfThenElseExec(
			conf.ValidateAllSignatures != nil,
			func() bool { return *conf.ValidateAllSignatures },
			func() bool { return len(conf.Tag) == 0 },
		),
		sf:                    &conf.PrincipalInfo,
		errorSignalingEnabled: conf.ErrorSignaling.Enabled != nil && *conf.ErrorSignaling.Enabled,
		informer:              informer,
	}
}

func newHTTPMessageSignaturesKeyInformer(
	resolver secrets.Resolver,
	keyStore config.Secret,
) (*secrets.SecretSetInformer[[]httpsig.Key], error) {
	return secrets.NewSecretSetInformer(
		resolver,
		secrets.Reference{Source: keyStore.Source, Selector: keyStore.Selector},
		secrets.WithConverter(toHTTPSigVerificationKeys),
	)
}

func (a *httpMessageSignaturesAuthenticator) Accept(visitor pipeline.Visitor) {
	visitor.VisitInsecure(a)
	visitor.VisitPrincipalNamer(a)
}

func (a *httpMessageSignaturesAuthenticator) Execute(ctx pipeline.Context, sub pipeline.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", AuthenticatorHTTPMessageSignatures).
		Str("_name", a.name).
		Str("_id", a.id).
		Msg("Executing authenticator")

	keys, ok := a.informer.Get()
	if !ok {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"http message signature verification keys are not available",
		)
	}

	resolver := &recordingHTTPSigKeyResolver{keys: keys}

	verifier, err := httpsig.NewVerifier(resolver, a.verifierOptions(a.errorSignalingEnabled)...)
	if err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed creating http message signatures verifier",
		).CausedBy(err)
	}

	msg, err := toHTTPMessageSignatureMessage(ctx, a.maxBodySize)
	if err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrAuthentication,
			"failed creating http message signature verification request",
		).WithAspects(a).CausedBy(err)
	}

	if err = verifier.Verify(msg); err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrAuthentication,
			"http message signature verification failed",
		).WithAspects(a).CausedBy(err)
	}

	principal, err := a.sf.CreatePrincipal(resolver.principalData())
	if err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrAuthentication,
			"failed creating principal from verified http message signature",
		).WithAspects(a).CausedBy(err)
	}

	sub[a.principalName] = principal

	return nil
}

func toHTTPMessageSignatureMessage(ctx pipeline.Context, maxBodySize bytesize.ByteSize) (*httpsig.Message, error) {
	msg, err := pipeline.HTTPMessageFromRequest(
		ctx.Context(),
		ctx.Request(),
		pipeline.WithMaxHTTPMessageBodySize(safecast.MustConvert[int64](uint64(maxBodySize))),
	)
	if err != nil {
		return nil, err
	}

	return &httpsig.Message{
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
	}, nil
}

func (a *httpMessageSignaturesAuthenticator) CreateStep(
	resolver secrets.Resolver,
	def types.StepDefinition,
) (pipeline.Step, error) {
	if def.IsEmpty() {
		return a, nil
	}

	if len(def.Config) == 0 {
		auth := *a
		auth.id = x.IfThenElse(len(def.ID) == 0, a.id, def.ID)
		auth.principalName = x.IfThenElse(len(def.Principal) == 0, a.principalName, def.Principal)

		return &auth, nil
	}

	conf, err := decodeHTTPMessageSignaturesConfig(a.app, a.name, def.Config)
	if err != nil {
		return nil, err
	}

	informer, err := newHTTPMessageSignaturesKeyInformer(resolver, conf.KeyStore)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed creating http message signatures key informer",
		).CausedBy(err)
	}

	return newHTTPMessageSignaturesAuthenticatorFromConfig(
		a.app,
		a.name,
		x.IfThenElse(len(def.ID) == 0, a.id, def.ID),
		x.IfThenElse(len(def.Principal) == 0, a.principalName, def.Principal),
		conf,
		informer,
	), nil
}

func (a *httpMessageSignaturesAuthenticator) DecorateErrorResponse(err error, er *pipeline.ErrorResponse) {
	if !a.errorSignalingEnabled {
		return
	}

	var noApplicableSignature *httpsig.NoApplicableSignatureError
	if !errors.As(err, &noApplicableSignature) {
		return
	}

	er.Code = http.StatusUnauthorized

	header := http.Header{}
	noApplicableSignature.Negotiate(header)

	for name, values := range header {
		for _, value := range values {
			er.AddHeader(name, value)
		}
	}
}

func (a *httpMessageSignaturesAuthenticator) Name() string          { return a.name }
func (a *httpMessageSignaturesAuthenticator) ID() string            { return a.id }
func (a *httpMessageSignaturesAuthenticator) Type() string          { return a.name }
func (a *httpMessageSignaturesAuthenticator) PrincipalName() string { return a.principalName }
func (*httpMessageSignaturesAuthenticator) Kind() types.Kind        { return types.KindAuthenticator }
func (*httpMessageSignaturesAuthenticator) IsInsecure() bool        { return false }

func (a *httpMessageSignaturesAuthenticator) verifierOptions(negotiate bool) []httpsig.VerifierOption {
	reqOpts := []httpsig.VerifierOption{
		httpsig.WithRequiredComponents(a.requiredComponents...),
		httpsig.WithMaxAge(a.maxAge),
		httpsig.WithValidityTolerance(a.allowedTimeSkew),
	}

	if a.createdTimestampRequired != nil {
		reqOpts = append(reqOpts, httpsig.WithCreatedTimestampRequired(*a.createdTimestampRequired))
	}

	if a.expiresTimestampRequired != nil {
		reqOpts = append(reqOpts, httpsig.WithExpiredTimestampRequired(*a.expiresTimestampRequired))
	}

	if negotiate && len(a.tag) != 0 {
		reqOpts = append(reqOpts, httpsig.WithSignatureNegotiation())
	}

	if len(a.tag) != 0 {
		return []httpsig.VerifierOption{httpsig.WithRequiredTag(a.tag, reqOpts...)}
	}

	opts := reqOpts
	if a.validateAllSignatures {
		opts = append(opts, httpsig.WithValidateAllSignatures())
	}

	return opts
}

type recordingHTTPSigKeyResolver struct {
	keys       []httpsig.Key
	resolvedID string
}

func (r *recordingHTTPSigKeyResolver) ResolveKey(_ context.Context, keyID string) (httpsig.Key, error) {
	for _, key := range r.keys {
		if key.KeyID == keyID {
			r.resolvedID = keyID

			return key, nil
		}
	}

	return httpsig.Key{}, errorchain.NewWithMessagef(
		pipeline.ErrAuthentication,
		"no http message signature verification key found for key id '%s'", keyID,
	)
}

func (r *recordingHTTPSigKeyResolver) principalData() []byte {
	data, _ := json.Marshal(map[string]any{"key_id": r.resolvedID})

	return data
}

func toHTTPSigVerificationKeys(secretSet []secrets.Secret) ([]httpsig.Key, error) {
	keys := make([]httpsig.Key, 0, len(secretSet))

	for _, secret := range secretSet {
		switch key := secret.(type) {
		case secrets.AsymmetricKeySecret:
			httpSigKey, err := asymmetricSecretToHTTPSigVerificationKey(key)
			if err != nil {
				return nil, err
			}

			keys = append(keys, httpSigKey)
		case secrets.SymmetricKeySecret:
			httpSigKey, err := symmetricSecretToHTTPSigVerificationKey(key)
			if err != nil {
				return nil, err
			}

			keys = append(keys, httpSigKey)
		default:
			return nil, errorchain.NewWithMessagef(
				pipeline.ErrConfiguration,
				"resolved secret '%s' is not suitable for http message signature verification",
				secret.Selector(),
			)
		}
	}

	if len(keys) == 0 {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"no http message signature verification keys configured",
		)
	}

	return keys, nil
}

func asymmetricSecretToHTTPSigVerificationKey(secret secrets.AsymmetricKeySecret) (httpsig.Key, error) {
	privateKey := secret.PrivateKey()
	if privateKey == nil {
		return httpsig.Key{}, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"resolved asymmetric secret '%s' does not contain private key material",
			secret.Selector(),
		)
	}

	publicKey := privateKey.Public()

	alg, err := signatureAlgorithm(publicKey)
	if err != nil {
		return httpsig.Key{}, err
	}

	return httpsig.Key{
		KeyID:     secret.KeyID(),
		Algorithm: alg,
		Key:       publicKey,
	}, nil
}

func symmetricSecretToHTTPSigVerificationKey(secret secrets.SymmetricKeySecret) (httpsig.Key, error) {
	alg, err := hmacSignatureAlgorithm(secret.Algorithm())
	if err != nil {
		return httpsig.Key{}, err
	}

	return httpsig.Key{
		KeyID:     secret.KeyID(),
		Algorithm: alg,
		Key:       secret.Key(),
	}, nil
}

func signatureAlgorithm(publicKey any) (httpsig.SignatureAlgorithm, error) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return rsaSignatureAlgorithm(key.Size() * 8) //nolint:mnd
	case *ecdsa.PublicKey:
		return ecdsaSignatureAlgorithm(key.Params().BitSize)
	case ed25519.PublicKey:
		return httpsig.Ed25519, nil
	default:
		return "", errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"unsupported http message signature verification key type: %T",
			publicKey,
		)
	}
}

func rsaSignatureAlgorithm(keySize int) (httpsig.SignatureAlgorithm, error) {
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
			"unsupported RSA key size for http message signature verification: %d",
			keySize,
		)
	}
}

func ecdsaSignatureAlgorithm(keySize int) (httpsig.SignatureAlgorithm, error) {
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
			"unsupported ECDSA key size for http message signature verification: %d",
			keySize,
		)
	}
}

func hmacSignatureAlgorithm(alg string) (httpsig.SignatureAlgorithm, error) {
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
			"unsupported HMAC algorithm for http message signature verification: %s",
			alg,
		)
	}
}
