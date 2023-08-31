package rules

import (
	"net/url"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ruleExecutor struct {
	r rule.Repository
}

func newRuleExecutor(repository rule.Repository) rule.Executor {
	return &ruleExecutor{r: repository}
}

func (e *ruleExecutor) Execute(ctx heimdall.Context, requireURL bool) (*url.URL, error) {
	req := ctx.Request()

	//nolint:contextcheck
	zerolog.Ctx(ctx.AppContext()).Debug().
		Str("_method", req.Method).
		Str("_url", req.URL.String()).
		Msg("Analyzing request")

	rul, err := e.r.FindRule(req.URL)
	if err != nil {
		return nil, err
	}

	method := ctx.Request().Method
	if !rul.MatchesMethod(method) {
		return nil, errorchain.NewWithMessagef(heimdall.ErrMethodNotAllowed,
			"rule (id=%s, src=%s) doesn't match %s method", rul.ID(), rul.SrcID(), method)
	}

	mut, err := rul.Execute(ctx)
	if err != nil {
		return nil, err
	}

	if requireURL {
		return mut.Mutate(ctx.Request().URL)
	}

	return &url.URL{}, nil
}
