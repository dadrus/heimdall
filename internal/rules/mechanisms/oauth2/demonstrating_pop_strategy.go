package oauth2

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/go-viper/mapstructure/v2"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/nonce"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

var (
	ErrDPoPProof = errors.New("DPoP proof error")
	ErrDPoPNonce = errors.New("DPoP nonce error")
)

type binder [32]byte

func (b binder) Binding() [32]byte { return b }

type nonceKey nonce.Key

func (k nonceKey) NonceKey() nonce.Key { return nonce.Key(k) }

func toNonceKeyResolver(secret secrets.Secret) (nonce.KeyResolver, error) {
	ss, ok := secret.(secrets.StringSecret)
	if !ok {
		return nil, secrets.ErrSecretKindMismatch
	}

	nk := nonce.Key{
		KID:   secret.Selector(),
		Value: stringx.ToBytes(ss.Value()),
	}

	return nonce.KeyResolverFunc(func(kid string) (nonce.Key, error) {
		if kid != nk.KID {
			return nonce.Key{}, errorchain.NewWithMessage(
				ErrDPoPNonce,
				"key id referenced in nonce does not match master key",
			)
		}

		return nk, nil
	}), nil
}

type demonstratingPoPStrategy struct {
	MaxAge        time.Duration `mapstructure:"max_age"`
	RequireNonce  *bool         `mapstructure:"nonce_required"`
	ReplayAllowed *bool         `mapstructure:"replay_allowed"`

	informer *secrets.SecretInformer[nonce.KeyResolver]
}

func newDemonstratingPoPStrategy(ctx app.Context, conf map[string]any) (PopStrategy, error) {
	var strategy demonstratingPoPStrategy

	dec := ctx.DecoderFactory().Decoder(
		encoding.WithTagName("mapstructure"),
		encoding.WithDecodeHooks(
			mapstructure.StringToTimeDurationHookFunc(),
		),
		encoding.WithErrorOnUnused(true),
	)

	if err := dec.DecodeMap(&strategy, conf); err != nil {
		return nil, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"failed decoding DPoP config",
		)
	}

	nonceRequired := strategy.RequireNonce != nil && *strategy.RequireNonce
	if !nonceRequired {
		return &strategy, nil
	}

	secret := ctx.Config().MasterKey
	if len(secret.Source) == 0 {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"master_key is required if DPoP nonce validation is enabled",
		)
	}

	informer, err := secrets.NewSecretInformer(
		ctx.SecretResolver(),
		secrets.Reference{Source: secret.Source, Selector: secret.Selector},
		secrets.WithConverter(toNonceKeyResolver),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed resolving master key secret",
		).CausedBy(err)
	}

	strategy.informer = informer

	return &strategy, nil
}

func (s *demonstratingPoPStrategy) Merge(other PopStrategy) PopStrategy {
	if other == nil {
		return s
	}

	typed, ok := other.(*demonstratingPoPStrategy)
	if !ok {
		return s
	}

	s.MaxAge = x.IfThenElse(s.MaxAge != 0, s.MaxAge, typed.MaxAge)
	s.RequireNonce = x.IfThenElse(s.RequireNonce != nil,
		s.RequireNonce, typed.RequireNonce)
	s.ReplayAllowed = x.IfThenElse(s.ReplayAllowed != nil,
		s.ReplayAllowed, typed.ReplayAllowed)

	return s
}

func (s *demonstratingPoPStrategy) Assert(
	ctx pipeline.Context,
	cnf *Confirmation,
	rawToken string,
	leeway time.Duration,
	allowedAlgorithms []jose.SignatureAlgorithm,
) error {
	if cnf == nil {
		return errorchain.NewWithMessage(ErrDPoPProof, "proof of possession is required")
	}

	if len(cnf.JWKThumbprint) == 0 {
		return errorchain.NewWithMessage(ErrDPoPProof, "no JWT thumbprint present")
	}

	authValue := ctx.Request().Header("Authorization")
	if !strings.HasPrefix(authValue, "DPoP ") {
		return errorchain.NewWithMessage(ErrDPoPProof, "malformed token scheme - DPoP expected")
	}

	proof := ctx.Request().Header("DPoP")
	if len(proof) == 0 {
		return errorchain.NewWithMessage(ErrDPoPProof, "proof is missing")
	}

	token, err := jwt.ParseSigned(proof, allowedAlgorithms)
	if err != nil {
		return errorchain.NewWithMessage(ErrDPoPProof, "failed to parse proof").
			CausedBy(pipeline.ErrMalformedRequest).
			CausedBy(err)
	}

	header := token.Headers[0]
	if header.ExtraHeaders[jose.HeaderType] != "dpop+jwt" {
		return errorchain.NewWithMessage(ErrDPoPProof, "invalid typ header")
	}

	if header.JSONWebKey == nil {
		return errorchain.NewWithMessage(ErrDPoPProof, "no JWK present")
	}

	if !header.JSONWebKey.Valid() {
		return errorchain.NewWithMessage(ErrDPoPProof, "invalid public JWK")
	}

	jkt, err := header.JSONWebKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return errorchain.NewWithMessage(pipeline.ErrInternal, "failed to calculate JWK thumbprint").
			CausedBy(err)
	}

	if base64.RawURLEncoding.EncodeToString(jkt) != cnf.JWKThumbprint {
		return errorchain.NewWithMessage(ErrDPoPProof, "proof key does not match access token binding")
	}

	var claims DPoPProofClaims
	if err = token.Claims(header.JSONWebKey, &claims); err != nil {
		return errorchain.NewWithMessage(ErrDPoPProof, "failed to verify signature").
			CausedBy(err)
	}

	replayAllowed := false
	if s.ReplayAllowed != nil {
		replayAllowed = *s.ReplayAllowed
	}

	nonceRequired := false
	if s.RequireNonce != nil {
		nonceRequired = *s.RequireNonce
	}

	keyResolver, ok := s.informer.Get()
	if !ok {
		keyResolver = nonce.KeyResolverFunc(func(kid string) (nonce.Key, error) {
			return nonce.Key{}, errorchain.NewWithMessage(
				pipeline.ErrInternal,
				"master key is not available",
			)
		})
	}

	return claims.Validate(ctx, keyResolver, s.MaxAge, leeway, replayAllowed, nonceRequired, rawToken)
}

type DPoPProofClaims struct {
	HTTPMethod      string    `json:"htm"`
	HTTPURI         string    `json:"htu"`
	AccessTokenHash string    `json:"ath"`
	IssuedAt        time.Time `json:"iat"`
	JTI             string    `json:"jti"`
	Nonce           string    `json:"nonce,omitempty"`
}

//nolint:cyclop
func (c DPoPProofClaims) Validate(
	ctx pipeline.Context,
	keyResolver nonce.KeyResolver,
	maxAge, leeway time.Duration,
	replayAllowed, nonceRequired bool,
	rawToken string,
) error {
	httpURI := ctx.Request().URL.URL
	httpURI.RawQuery = ""
	httpURI.Fragment = ""

	expectedHash := sha256.Sum256(stringx.ToBytes(rawToken))
	now := time.Now()
	cch := cache.Ctx(ctx.Context())

	var jtiKey string

	if len(c.JTI) == 0 {
		return errorchain.NewWithMessage(ErrDPoPProof, "jti is missing")
	}

	if !replayAllowed {
		jtiHash := sha256.Sum256(stringx.ToBytes(c.JTI))
		jtiKey = "dpop:jti:" + base64.RawURLEncoding.EncodeToString(jtiHash[:])

		if _, err := cch.Get(ctx.Context(), jtiKey); err == nil {
			return errorchain.NewWithMessage(ErrDPoPProof, "replay detected")
		}
	}

	if c.IssuedAt.IsZero() {
		return errorchain.NewWithMessage(ErrDPoPProof, "iat is missing")
	}

	if now.Add(leeway).Before(c.IssuedAt) {
		return errorchain.NewWithMessage(ErrDPoPProof, "iat is in the future")
	}

	ttl := time.Until(c.IssuedAt.Add(maxAge).Add(leeway))
	if ttl <= 0 {
		return errorchain.NewWithMessage(ErrDPoPProof, "proof is too old")
	}

	if c.HTTPMethod != ctx.Request().Method {
		return errorchain.NewWithMessage(ErrDPoPProof, "htm does not match request method")
	}

	if c.HTTPURI != httpURI.String() {
		return errorchain.NewWithMessage(ErrDPoPProof, "htu does not match request URI")
	}

	gotHash, _ := base64.RawURLEncoding.DecodeString(c.AccessTokenHash)
	if subtle.ConstantTimeCompare(expectedHash[:], gotHash) != 1 {
		return errorchain.NewWithMessage(ErrDPoPProof, "ath does not match expected token hash value")
	}

	if nonceRequired {
		if len(c.Nonce) == 0 {
			return errorchain.New(ErrDPoPProof).
				WithAspects(binder(expectedHash)).
				CausedBy(errorchain.NewWithMessage(ErrDPoPNonce, "nonce is missing"))
		}

		if err := nonce.ValidateNonce(c.Nonce, keyResolver,
			nonce.WithMaxAge(maxAge),
			nonce.WithBinding(expectedHash),
		); err != nil {
			return errorchain.New(ErrDPoPNonce).
				WithAspects(binder(expectedHash)).
				CausedBy(err)
		}
	}

	if !replayAllowed {
		if err := cch.Set(ctx.Context(), jtiKey, []byte{1}, ttl); err != nil {
			return errorchain.NewWithMessage(pipeline.ErrInternal,
				"failed to remember DPoP proof jti").CausedBy(err)
		}
	}

	return nil
}

func (s *demonstratingPoPStrategy) init(ctx app.Context) error {
	return nil
}
