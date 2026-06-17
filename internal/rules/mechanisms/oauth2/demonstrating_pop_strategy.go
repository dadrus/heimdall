package oauth2

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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

type nonceManager struct {
	current nonce.Key
	keys    []nonce.Key
}

func (m nonceManager) ResolveKey(kid string) (nonce.Key, error) {
	for _, k := range m.keys {
		if k.KID == kid {
			return k, nil
		}
	}

	return nonce.Key{}, errorchain.NewWithMessage(
		ErrDPoPNonce,
		"key id referenced in nonce does not match any known master key",
	)
}

func (m nonceManager) IssueNonce(binding [32]byte) (string, error) {
	return nonce.NewNonce(m.current, nonce.WithBinding(binding))
}

func makeNonceManagerConverter(ref secrets.Reference) secrets.SecretSetConverter[nonceManager] {
	currentKID := ref.Selector
	if idx := strings.LastIndex(ref.Selector, "/"); idx >= 0 {
		currentKID = ref.Selector[idx+1:]
	}

	return func(keySet []secrets.Secret) (nonceManager, error) {
		var mgr nonceManager

		for _, secret := range keySet {
			sym, ok := secret.(secrets.SymmetricKeySecret)
			if !ok {
				continue
			}

			key := nonce.Key{KID: sym.KeyID(), Value: sym.Key()}
			mgr.keys = append(mgr.keys, key)

			if sym.KeyID() == currentKID {
				mgr.current = key
			}
		}

		if len(mgr.current.KID) == 0 {
			return nonceManager{}, errorchain.NewWithMessage(
				ErrDPoPNonce,
				"current master key not found in key set",
			)
		}

		return mgr, nil
	}
}

type demonstratingPoPStrategy struct {
	MaxAge        time.Duration `mapstructure:"max_age"`
	RequireNonce  *bool         `mapstructure:"nonce_required"`
	ReplayAllowed *bool         `mapstructure:"replay_allowed"`

	setInformer *secrets.SecretSetInformer[nonceManager]
}

func newDemonstratingPoPStrategy(ctx app.Context, conf map[string]any) (PoPStrategy, error) {
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

	ref := secrets.Reference{Source: secret.Source, Selector: secret.Selector}

	setInformer, err := secrets.NewSecretSetInformer(
		ctx.SecretResolver(),
		ref.Parent(),
		secrets.WithConverter(makeNonceManagerConverter(ref)),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed resolving master key secret",
		).CausedBy(err)
	}

	strategy.setInformer = setInformer

	return &strategy, nil
}

func (s *demonstratingPoPStrategy) Merge(other PoPStrategy) PoPStrategy {
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

//nolint:cyclop, funlen
func (s *demonstratingPoPStrategy) Assert(
	ctx pipeline.Context,
	token *Token,
	leeway time.Duration,
	allowedAlgorithms []jose.SignatureAlgorithm,
) error {
	cnf := token.Claims.Confirmation

	if cnf == nil {
		return NewInvalidDPoPProofError("proof of possession is required")
	}

	// we're not assuming a token type. it must be explicitly specified
	if len(token.Type) == 0 && len(token.Claims.TokenType) == 0 {
		return NewInvalidDPoPProofError("malformed token type - DPoP expected")
	}

	if len(token.Type) != 0 && token.Type != TypeDPoP {
		return NewInvalidDPoPProofError("malformed token type - DPoP expected")
	}

	// RFC 9449 §6.2: If the token_type member is included in the
	// introspection response, it MUST contain the value DPoP.
	if len(token.Claims.TokenType) != 0 && token.Claims.TokenType != TypeDPoP {
		return NewInvalidDPoPProofError("malformed token type - DPoP expected")
	}

	if len(cnf.JWKThumbprint) == 0 {
		return NewInvalidDPoPProofError("no JWT thumbprint present")
	}

	proof := ctx.Request().Header("DPoP")
	if len(proof) == 0 {
		return NewInvalidDPoPProofError("proof is missing")
	}

	proofJWT, err := jwt.ParseSigned(proof, allowedAlgorithms)
	if err != nil {
		return errorchain.New(NewInvalidDPoPProofError("failed to parse proof")).
			CausedBy(err)
	}

	header := proofJWT.Headers[0]
	if header.ExtraHeaders[jose.HeaderType] != "dpop+jwt" {
		return NewInvalidDPoPProofError("invalid typ header")
	}

	if header.JSONWebKey == nil {
		return NewInvalidDPoPProofError("no JWK present")
	}

	if !header.JSONWebKey.Valid() {
		return NewInvalidDPoPProofError("invalid public JWK")
	}

	jkt, err := header.JSONWebKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrInternal,
			"failed to calculate JWK thumbprint",
		).CausedBy(err)
	}

	if base64.RawURLEncoding.EncodeToString(jkt) != cnf.JWKThumbprint {
		return NewInvalidDPoPProofError("proof key does not match access token binding")
	}

	var proofClaims DPoPProofClaims
	if err = proofJWT.Claims(header.JSONWebKey, &proofClaims); err != nil {
		return errorchain.New(NewInvalidDPoPProofError("failed to verify signature")).
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

	var mgr nonceManager

	if nonceRequired {
		var ok bool

		mgr, ok = s.setInformer.Get()
		if !ok {
			return errorchain.NewWithMessage(
				pipeline.ErrInternal,
				"master key is not available",
			)
		}
	}

	return proofClaims.Validate(ctx, mgr, s.MaxAge, leeway, replayAllowed, nonceRequired, token.Raw)
}

type DPoPProofClaims struct {
	HTTPMethod      string    `json:"htm"`
	HTTPURI         string    `json:"htu"`
	AccessTokenHash string    `json:"ath"`
	IssuedAt        time.Time `json:"iat"`
	JTI             string    `json:"jti"`
	Nonce           string    `json:"nonce,omitempty"`
}

//nolint:cyclop, funlen
func (c DPoPProofClaims) Validate(
	ctx pipeline.Context,
	nonceHandler nonceManager,
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
		return NewInvalidDPoPProofError("jti is missing")
	}

	if !replayAllowed {
		jtiHash := sha256.Sum256(stringx.ToBytes(c.JTI))
		jtiKey = "dpop:jti:" + base64.RawURLEncoding.EncodeToString(jtiHash[:])

		if _, err := cch.Get(ctx.Context(), jtiKey); err == nil {
			return NewInvalidDPoPProofError("replay detected")
		}
	}

	if c.IssuedAt.IsZero() {
		return NewInvalidDPoPProofError("iat is missing")
	}

	if now.Add(leeway).Before(c.IssuedAt) {
		return NewInvalidDPoPProofError("iat is in the future")
	}

	ttl := time.Until(c.IssuedAt.Add(maxAge).Add(leeway))
	if ttl <= 0 {
		return NewInvalidDPoPProofError("proof is too old")
	}

	if c.HTTPMethod != ctx.Request().Method {
		return NewInvalidDPoPProofError("htm does not match request method")
	}

	if c.HTTPURI != httpURI.String() {
		return NewInvalidDPoPProofError("htu does not match request URI")
	}

	gotHash, err := base64.RawURLEncoding.DecodeString(c.AccessTokenHash)
	if err != nil {
		return NewInvalidDPoPProofError("ath is malformed")
	}

	if subtle.ConstantTimeCompare(expectedHash[:], gotHash) != 1 {
		return NewInvalidDPoPProofError("ath does not match expected token hash value")
	}

	if nonceRequired {
		if len(c.Nonce) == 0 {
			return NewUseDPoPNonceError(nonceHandler, expectedHash, "nonce is missing")
		}

		if err := nonce.ValidateNonce(
			c.Nonce,
			nonceHandler,
			nonce.WithMaxAge(maxAge),
			nonce.WithBinding(expectedHash),
		); err != nil {
			return errorchain.New(NewUseDPoPNonceError(nonceHandler, expectedHash, "nonce is invalid")).
				CausedBy(err)
		}
	}

	if !replayAllowed {
		if err := cch.Set(ctx.Context(), jtiKey, []byte{1}, ttl); err != nil {
			return errorchain.NewWithMessage(
				pipeline.ErrInternal,
				"failed to remember DPoP proof jti",
			).CausedBy(err)
		}
	}

	return nil
}

func (s *demonstratingPoPStrategy) init(ctx app.Context) error {
	return nil
}
