package rules

import (
	"context"
	"net/url"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type Rule interface {
	ID() string
	Execute(context.Context, handler.RequestContext) (*heimdall.SubjectContext, error)
	MatchesURL(*url.URL) bool
	MatchesMethod(string) bool
}
