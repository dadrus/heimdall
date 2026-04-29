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

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/nonce"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

var (
	ErrDPoPProof = errors.New("DPoP proof error")
	ErrDPoPNonce = errors.New("DPoP nonce error")
)

type PoPType string

const (
	Undefined PoPType = ""
	DPoP      PoPType = "dpop"
)

type binder [32]byte

func (b binder) Binding() [32]byte { return b }

type ProofOfPossession struct {
	Type   PoPType    `mapstructure:"type"`
	Config DPoPConfig `mapstructure:"config"`
}

type DPoPConfig struct {
	RequireNonce  *bool         `mapstructure:"require_nonce"`
	MaxAge        time.Duration `mapstructure:"max_age"`
	ReplayAllowed *bool         `mapstructure:"replay_allowed"`
}

func (p *ProofOfPossession) Merge(other ProofOfPossession) {
	p.Type = x.IfThenElse(len(p.Type) != 0, p.Type, other.Type)
	p.Config.MaxAge = x.IfThenElse(p.Config.MaxAge != 0, p.Config.MaxAge, other.Config.MaxAge)
	p.Config.RequireNonce = x.IfThenElse(p.Config.RequireNonce != nil,
		p.Config.RequireNonce, other.Config.RequireNonce)
	p.Config.ReplayAllowed = x.IfThenElse(p.Config.ReplayAllowed != nil,
		p.Config.ReplayAllowed, other.Config.ReplayAllowed)
}

func (p *ProofOfPossession) Assert(
	ctx pipeline.Context,
	cnf *Confirmation,
	rawToken string,
	leeway time.Duration,
	allowedAlgorithms []jose.SignatureAlgorithm,
) error {
	if cnf == nil {
		if p.Type != Undefined {
			return errorchain.NewWithMessage(ErrDPoPProof, "proof of possession is required")
		}

		return nil
	}

	// enforcing DPoP if configured
	// otherwise, only asserting if a JWK thumbprint is present in the cnf claim
	// x5t#S256 is defined for MTLS, which is not yet supported
	if p.Type == DPoP || len(cnf.JWKThumbprint) != 0 {
		return p.assertDPoP(ctx, cnf, rawToken, leeway, allowedAlgorithms)
	}

	return nil
}

func (p *ProofOfPossession) assertDPoP(
	ctx pipeline.Context,
	cnf *Confirmation,
	rawToken string,
	leeway time.Duration,
	allowedAlgorithms []jose.SignatureAlgorithm,
) error {
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
	if p.Config.ReplayAllowed != nil {
		replayAllowed = *p.Config.ReplayAllowed
	}

	nonceRequired := false
	if p.Config.RequireNonce != nil {
		nonceRequired = *p.Config.RequireNonce
	}

	return claims.Validate(ctx, p.Config.MaxAge, leeway, replayAllowed, nonceRequired, rawToken)
}

type DPoPProofClaims struct {
	HTTPMethod      string    `json:"htm"`
	HTTPURI         string    `json:"htu"`
	AccessTokenHash string    `json:"ath"`
	IssuedAt        time.Time `json:"iat"`
	JTI             string    `json:"jti"`
	Nonce           string    `json:"nonce,omitempty"`
}

func (c DPoPProofClaims) Validate(
	ctx pipeline.Context,
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

		if err := nonce.ValidateNonce(c.Nonce, nil,
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
