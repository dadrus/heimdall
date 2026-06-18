package oauth2

import (
	"crypto"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/go-viper/mapstructure/v2"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/nonce"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var errKeyUnknown = errors.New("unknown key")

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
		errKeyUnknown,
		"key id referenced in nonce does not match any known master key",
	)
}

func (m nonceManager) IssueNonce(binding [32]byte) (string, error) {
	return nonce.NewNonce(m.current, nonce.WithBinding(binding))
}

type DPoPStrategy struct {
	MaxAge        time.Duration `mapstructure:"max_age"`
	RequireNonce  *bool         `mapstructure:"nonce_required"`
	ReplayAllowed *bool         `mapstructure:"replay_allowed"`

	setInformer *secrets.SecretSetInformer[nonceManager]
	currentKID  string
}

func newDPoPStrategy(ctx app.Context, conf map[string]any) (PoPStrategy, error) {
	var strategy DPoPStrategy

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

	if strategy.MaxAge == 0 {
		strategy.MaxAge = 1 * time.Minute
	}

	nonceRequired := strategy.RequireNonce != nil && *strategy.RequireNonce
	if !nonceRequired {
		return &strategy, nil
	}

	secret := ctx.Config().MasterKey
	if secret == nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"master_key is not configured, but required if DPoP nonce validation is enabled",
		)
	}

	ref := secrets.Reference{Source: secret.Source, Selector: secret.Selector}

	strategy.currentKID = ref.Selector
	if idx := strings.LastIndex(ref.Selector, "/"); idx >= 0 {
		strategy.currentKID = ref.Selector[idx+1:]
	}

	setInformer, err := secrets.NewSecretSetInformer(
		ctx.SecretResolver(),
		ref.Parent(),
		secrets.WithConverter(strategy.createNonceManager),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed creating nonce manager secret set informer",
		).CausedBy(err)
	}

	strategy.setInformer = setInformer

	return &strategy, nil
}

func (s *DPoPStrategy) Merge(other PoPStrategy) PoPStrategy {
	if other == nil {
		return s
	}

	typed, ok := other.(*DPoPStrategy)
	if !ok {
		return s
	}

	if s.MaxAge == 0 {
		s.MaxAge = typed.MaxAge
	}

	if s.RequireNonce == nil {
		s.RequireNonce = typed.RequireNonce

		if s.RequireNonce != nil && *s.RequireNonce {
			s.setInformer = typed.setInformer
			s.currentKID = typed.currentKID
		}
	}

	if s.ReplayAllowed == nil {
		s.ReplayAllowed = typed.ReplayAllowed
	}

	return s
}

//nolint:cyclop, funlen
func (s *DPoPStrategy) Assert(
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
		if _, ok := errors.AsType[*jose.ErrUnexpectedSignatureAlgorithm](err); ok {
			return errorchain.New(NewInvalidDPoPProofError("algorithm is not allowed", allowedAlgorithms...))
		}

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

	if !header.JSONWebKey.IsPublic() || !header.JSONWebKey.Valid() {
		// with header.JSONWebKey.IsPublic() we ensure no symmetric keys can be
		// used even though they would be allowed by allowedAlgorithms
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

	var proofClaims DPoPClaims
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

func (s *DPoPStrategy) createNonceManager(keySet []secrets.Secret) (nonceManager, error) {
	var mgr nonceManager

	for _, secret := range keySet {
		sym, ok := secret.(secrets.SymmetricKeySecret)
		if !ok {
			continue
		}

		key := nonce.Key{KID: sym.KeyID(), Value: sym.Key()}
		mgr.keys = append(mgr.keys, key)

		if sym.KeyID() == s.currentKID {
			mgr.current = key
		}
	}

	if len(mgr.current.KID) == 0 {
		return nonceManager{}, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"current master key not found in key set",
		)
	}

	return mgr, nil
}
