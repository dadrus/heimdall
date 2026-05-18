package source

import (
	"context"

	"github.com/dadrus/heimdall/internal/secrets/types"
)

type DependencyResolver interface {
	ResolveSecret(ctx context.Context, reference types.Reference) (types.Secret, error)
	ResolveCredentials(ctx context.Context, reference types.Reference) (types.Credentials, error)
}
