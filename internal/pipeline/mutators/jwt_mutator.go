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
		func(typ config.PipelineObjectType, conf map[string]any) (bool, Mutator, error) {
			if typ != config.POTJwt {
				return false, nil, nil
			}

			mut, err := newJWTMutator(conf)

			return true, mut, err
		})
}

type jwtMutator struct {
	jwksURL string
	claims  *Template
	issuer  string
	ttl     time.Duration
}

func newJWTMutator(rawConfig map[string]any) (*jwtMutator, error) {
	type _config struct {
		JWKSURL string `mapstructure:"jwks_url"`
		JWTBody struct {
			Claims *Template      `mapstructure:"claims"`
			Issuer string         `mapstructure:"issuer"`
			TTL    *time.Duration `mapstructure:"ttl"`
		} `mapstructure:"jwt_body"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal JWT mutator config").
			CausedBy(err)
	}

	ttl := defaultJWTTTL
	if conf.JWTBody.TTL != nil {
		ttl = *conf.JWTBody.TTL
	}

	return &jwtMutator{
		jwksURL: conf.JWKSURL,
		claims:  conf.JWTBody.Claims,
		issuer:  conf.JWTBody.Issuer,
		ttl:     ttl,
	}, nil
}

func (m *jwtMutator) Mutate(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Mutating using JWT mutator")

	var jwtToken string

	cch := cache.Ctx(ctx.AppContext())

	cacheKey, err := m.cacheKey(sub)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to calculate cache key. Will not be able to cache token")
	} else if item := cch.Get(cacheKey); item != nil {
		if cachedToken, ok := item.(string); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(cacheKey)
		} else {
			logger.Debug().Msg("Reusing token from cache")

			jwtToken = cachedToken
		}
	}

	if len(jwtToken) == 0 {
		jwtToken, err = m.generateToken(sub)
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

func (m *jwtMutator) WithConfig(config map[string]any) (Mutator, error) {
	return nil, nil
}

func (m *jwtMutator) generateToken(sub *subject.Subject) (string, error) {
	claims := map[string]any{}

	if m.claims != nil {
		vals, err := m.claims.Render(sub)
		if err != nil {
			return "", errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to render claims template").
				CausedBy(err)
		}

		if err := json.Unmarshal([]byte(vals), &claims); err != nil {
			return "", errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to unmarshal rendered claims template").
				CausedBy(err)
		}
	}

	now := time.Now().UTC()
	exp := now.Add(m.ttl)
	claims["exp"] = exp.Unix()
	claims["jti"] = uuid.New()
	claims["iat"] = now.Unix()
	claims["iss"] = m.issuer
	claims["nbf"] = now.Unix()
	claims["sub"] = sub.ID

	signerOpts := jose.SignerOptions{}
	signerOpts.
		WithType("JWT").
		WithHeader("kid", "bar").
		WithHeader("alg", "foo").
		WithHeader("jku", "foo")

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: nil}, &signerOpts)
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

func (m *jwtMutator) cacheKey(sub *subject.Subject) (string, error) {
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
	hash.Write([]byte(m.jwksURL))
	hash.Write([]byte(m.issuer))
	hash.Write([]byte(claims))
	hash.Write(ttlBytes)

	return hex.EncodeToString(hash.Sum(rawSub)), nil
}
