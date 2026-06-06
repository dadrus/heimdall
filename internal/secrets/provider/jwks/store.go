package jwks

import (
	"context"
	"os"

	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/go-jose/go-jose/v4"
	"github.com/goccy/go-json"
)

type store interface {
	getSecret(ctx context.Context, selector provider.Selector) (provider.Secret, error)
	getSecretSet(ctx context.Context, selector provider.Selector) ([]provider.Secret, error)
	getCertificateBundle(ctx context.Context, selector provider.Selector) (provider.CertificateBundle, error)

	sameKind(other store) bool
}

func loadStore(path string) (store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errorchain.NewWithMessagef(provider.ErrConfiguration,
			"failed to read jwks file %s", path).CausedBy(err)
	}

	var jwks jose.JSONWebKeySet
	if err = json.Unmarshal(data, &jwks); err != nil {
		return nil, errorchain.NewWithMessage(
			provider.ErrConfiguration,
			"failed to decode jwks file",
		).CausedBy(err)
	}

	return newKeyStore(jwks)
}