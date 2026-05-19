package types

import (
	"context"
	"strings"
)

type (
	Manager interface {
		ResolveSecret(ctx context.Context, reference Reference) (Secret, error)
		ResolveSecretSet(ctx context.Context, reference Reference) ([]Secret, error)
		ResolveCredentials(ctx context.Context, reference Reference) (Credentials, error)
		Subscribe(reference Reference, cb func(context.Context) error) (unsubscribe func(), err error)
	}

	Reference struct {
		Source      string
		Selector    string
		Namespace   string
		RuleContext bool
	}

	ReferenceFactory func(source, selector string) Reference
)

func (r Reference) Parent() Reference {
	if idx := strings.LastIndex(r.Selector, "/"); idx < 0 {
		r.Selector = ""
	} else {
		r.Selector = r.Selector[:idx]
	}

	return r
}
