package request

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

//go:generate mockery --name Context --structname ContextMock

type Context interface {
	heimdall.Context

	Finalize(rule.Backend) error
}
