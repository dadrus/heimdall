package rule

import "github.com/dadrus/heimdall/internal/heimdall"

type Route interface {
	Path() string
	Matches(ctx heimdall.Context, keys, values []string) bool
	Rule() Rule
}
