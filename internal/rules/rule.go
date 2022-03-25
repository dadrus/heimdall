package rules

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type Rule interface {
	Execute(ctx context.Context, ads interfaces.AuthDataSource) (*heimdall.SubjectContext, error)
}
