package keystore

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/rs/zerolog"
	"go.uber.org/fx"
)

// nolint
var Module = fx.Options(
	fx.Provide(newKeyStore),
)

func newKeyStore(conf config.Configuration, logger zerolog.Logger) (KeyStore, error) {
	if conf.Signer == nil {
		logger.Warn().Msg("Signer is not configured. Going to generate a key pair. NEVER DO IT IN PRODUCTION!!!!")

		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to generate RSA-2048 key pair").
				CausedBy(err)
		}

		return NewKeyStoreFromKey(privateKey)
	}

	return NewKeyStoreFromPEMFile(conf.Signer.File, conf.Signer.Password)
}
