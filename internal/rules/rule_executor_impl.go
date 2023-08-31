package rules

import (
	"net/url"

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
	rul, err := e.r.FindRule(ctx.Request().URL)
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
