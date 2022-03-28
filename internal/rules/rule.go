package rules

import (
	"context"
	"net/url"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type Rule interface {
	Id() string
	Execute(ctx context.Context, ads handler.AuthDataSource) (*heimdall.SubjectContext, error)
	MatchesUrl(requestUrl *url.URL) bool
	MatchesMethod(method string) bool
}
