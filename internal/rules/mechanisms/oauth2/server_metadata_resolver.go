package oauth2

import (
	"context"
)

type ServerMetadataResolver interface {
	Get(ctx context.Context, args map[string]any) (ServerMetadata, error)
}

type ResolverAdapterFunc func(ctx context.Context, args map[string]any) (ServerMetadata, error)

func (f ResolverAdapterFunc) Get(ctx context.Context, args map[string]any) (ServerMetadata, error) {
	return f(ctx, args)
}
