package mutators

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/pipeline/template"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const (
	defaultJWTTTL      = 15 * time.Minute
	defaultCacheLeeway = 10 * time.Second
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerMutatorTypeFactory(
		func(_ string, typ config.PipelineObjectType, conf map[any]any) (bool, Mutator, error) {
			if typ != config.POTJwt {
				return false, nil, nil
			}

			mut, err := newJWTMutator(conf)

			return true, mut, err
		})
}

type jwtMutator struct {
	claims *template.Template
	ttl    time.Duration
}

func newJWTMutator(rawConfig map[any]any) (*jwtMutator, error) {
	type _config struct {
		Claims *template.Template `mapstructure:"claims"`
		TTL    *time.Duration     `mapstructure:"ttl"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal JWT mutator config").
			CausedBy(err)
	}

	ttl := defaultJWTTTL
	if conf.TTL != nil {
		ttl = *conf.TTL
	}

	return &jwtMutator{
		claims: conf.Claims,
		ttl:    ttl,
	}, nil
}

func (m *jwtMutator) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Mutating using JWT mutator")

	if sub == nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to execute jwt mutator due to 'nil' subject")
	}

	var jwtToken string

	cch := cache.Ctx(ctx.AppContext())

	cacheKey, err := m.calculateCacheKey(sub, ctx.Signer())
	if err != nil {
		logger.Error().Err(err).Msg("Failed to calculate cache key. Will not be able to cache token")
	} else if item := cch.Get(cacheKey); item != nil {
		if cachedToken, ok := item.(string); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(cacheKey)
		} else {
			logger.Debug().Msg("Reusing JWT from cache")

			jwtToken = cachedToken
		}
	}

	if len(jwtToken) == 0 {
		logger.Debug().Msg("Generating new JWT")

		jwtToken, err = m.generateToken(ctx, sub)
		if err != nil {
			return err
		}

		if len(cacheKey) != 0 {
			cch.Set(cacheKey, jwtToken, m.ttl-defaultCacheLeeway)
		}
	}

	ctx.AddResponseHeader("Authorization", fmt.Sprintf("Bearer %s", jwtToken))

	return nil
}

func (m *jwtMutator) WithConfig(rawConfig map[any]any) (Mutator, error) {
	if len(rawConfig) == 0 {
		return m, nil
	}

	type _config struct {
		Claims *template.Template `mapstructure:"claims"`
		TTL    *time.Duration     `mapstructure:"ttl"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal JWT mutator config").
			CausedBy(err)
	}

	var ttl time.Duration
	if conf.TTL != nil {
		ttl = *conf.TTL
	} else {
		ttl = m.ttl
	}

	return &jwtMutator{
		claims: x.IfThenElse(conf.Claims != nil, conf.Claims, m.claims),
		ttl:    ttl,
	}, nil
}

func (m *jwtMutator) generateToken(ctx heimdall.Context, sub *subject.Subject) (string, error) {
	iss := ctx.Signer()

	claims := map[string]any{}
	if m.claims != nil {
		vals, err := m.claims.Render(nil, sub)
		if err != nil {
			return "", errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to render claims template").
				CausedBy(err)
		}

		if err := json.Unmarshal([]byte(vals), &claims); err != nil {
			return "", errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to unmarshal claims rendered by template").
				CausedBy(err)
		}
	}

	now := time.Now().UTC()
	exp := now.Add(m.ttl)
	claims["exp"] = exp.Unix()
	claims["jti"] = uuid.New()
	claims["iat"] = now.Unix()
	claims["iss"] = iss.Name()
	claims["nbf"] = now.Unix()
	claims["sub"] = sub.ID

	signerOpts := jose.SignerOptions{}
	signerOpts.
		WithType("JWT").
		WithHeader("kid", iss.KeyID()).
		WithHeader("alg", iss.Algorithm())

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: iss.Algorithm(),
			Key:       iss.Key(),
		},
		&signerOpts)
	if err != nil {
		return "", errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to create JWT signer").
			CausedBy(err)
	}

	builder := jwt.Signed(signer).Claims(claims)

	rawJwt, err := builder.CompactSerialize()
	if err != nil {
		return "", errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to sign JWT").
			CausedBy(err)
	}

	return rawJwt, nil
}

func (m *jwtMutator) calculateCacheKey(sub *subject.Subject, iss heimdall.JWTSigner) (string, error) {
	const int64BytesCount = 8

	claims := "null"
	if m.claims != nil {
		claims = string(*m.claims)
	}

	rawSub, err := json.Marshal(sub)
	if err != nil {
		return "", errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to marshal subject data").
			CausedBy(err)
	}

	ttlBytes := make([]byte, int64BytesCount)
	binary.LittleEndian.PutUint64(ttlBytes, uint64(m.ttl))

	hash := sha256.New()
	hash.Write([]byte(iss.KeyID()))
	hash.Write([]byte(iss.Algorithm()))
	hash.Write([]byte(iss.Name()))
	hash.Write([]byte(claims))
	hash.Write(ttlBytes)
	hash.Write(rawSub)

	return hex.EncodeToString(hash.Sum(nil)), nil
}
