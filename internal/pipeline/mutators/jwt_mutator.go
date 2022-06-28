package mutators

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/pipeline/template"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const (
	defaultJWTTTL      = 5 * time.Minute
	defaultCacheLeeway = 5 * time.Second
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerMutatorTypeFactory(
		func(_ string, typ config.PipelineObjectType, conf map[string]any) (bool, Mutator, error) {
			if typ != config.POTJwt {
				return false, nil, nil
			}

			mut, err := newJWTMutator(conf)

			return true, mut, err
		})
}

type jwtMutator struct {
	claims template.Template
	ttl    time.Duration
}

func newJWTMutator(rawConfig map[string]any) (*jwtMutator, error) {
	type _config struct {
		Claims template.Template `mapstructure:"claims"`
		TTL    *time.Duration    `mapstructure:"ttl"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed to unmarshal JWT mutator config").CausedBy(err)
	}

	if conf.TTL != nil && *conf.TTL <= 1*time.Second {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"configured JWT ttl is less than one second")
	}

	return &jwtMutator{
		claims: conf.Claims,
		ttl: x.IfThenElseExec(conf.TTL != nil,
			func() time.Duration { return *conf.TTL },
			func() time.Duration { return defaultJWTTTL }),
	}, nil
}

func (m *jwtMutator) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Mutating using JWT mutator")

	if sub == nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to execute jwt mutator due to 'nil' subject")
	}

	cch := cache.Ctx(ctx.AppContext())

	var (
		cacheEntry any
		jwtToken   string
		ok         bool
	)

	cacheKey, err := m.calculateCacheKey(sub, ctx.Signer())
	if err != nil {
		logger.Error().Err(err).Msg("Failed to calculate cache key. Will not be able to cache token")
	} else {
		cacheEntry = cch.Get(cacheKey)
	}

	if cacheEntry != nil {
		if jwtToken, ok = cacheEntry.(string); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(cacheKey)
		} else {
			logger.Debug().Msg("Reusing JWT from cache")
		}
	}

	if len(jwtToken) == 0 {
		logger.Debug().Msg("Generating new JWT")

		jwtToken, err = m.generateToken(ctx, sub)
		if err != nil {
			return err
		}

		if len(cacheKey) != 0 && m.ttl > defaultCacheLeeway {
			cch.Set(cacheKey, jwtToken, m.ttl-defaultCacheLeeway)
		}
	}

	ctx.AddResponseHeader("Authorization", fmt.Sprintf("Bearer %s", jwtToken))

	return nil
}

func (m *jwtMutator) WithConfig(rawConfig map[string]any) (Mutator, error) {
	if len(rawConfig) == 0 {
		return m, nil
	}

	type _config struct {
		Claims template.Template `mapstructure:"claims"`
		TTL    *time.Duration    `mapstructure:"ttl"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed to unmarshal JWT mutator config").CausedBy(err)
	}

	if conf.TTL != nil && *conf.TTL < 1*time.Second {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"configured JWT ttl is less than one second")
	}

	return &jwtMutator{
		claims: x.IfThenElse(conf.Claims != nil, conf.Claims, m.claims),
		ttl: x.IfThenElseExec(conf.TTL != nil,
			func() time.Duration { return *conf.TTL },
			func() time.Duration { return m.ttl }),
	}, nil
}

func (m *jwtMutator) generateToken(ctx heimdall.Context, sub *subject.Subject) (string, error) {
	iss := ctx.Signer()

	claims := map[string]any{}
	if m.claims != nil {
		vals, err := m.claims.Render(nil, sub)
		if err != nil {
			return "", errorchain.NewWithMessage(heimdall.ErrInternal,
				"failed to render claims").CausedBy(err)
		}

		if err := json.Unmarshal([]byte(vals), &claims); err != nil {
			return "", errorchain.NewWithMessage(heimdall.ErrInternal,
				"failed to unmarshal claims rendered by template").CausedBy(err)
		}
	}

	return iss.Sign(sub.ID, m.ttl, claims)
}

func (m *jwtMutator) calculateCacheKey(sub *subject.Subject, iss heimdall.JWTSigner) (string, error) {
	const int64BytesCount = 8

	rawSub, err := json.Marshal(sub)
	if err != nil {
		return "", errorchain.NewWithMessage(heimdall.ErrInternal, "failed to marshal subject data").
			CausedBy(err)
	}

	ttlBytes := make([]byte, int64BytesCount)
	binary.LittleEndian.PutUint64(ttlBytes, uint64(m.ttl))

	hash := sha256.New()
	hash.Write([]byte(iss.Hash()))
	hash.Write([]byte(x.IfThenElseExec(m.claims != nil,
		func() string { return m.claims.Hash() },
		func() string { return "null" })))
	hash.Write(ttlBytes)
	hash.Write(rawSub)

	return hex.EncodeToString(hash.Sum(nil)), nil
}
