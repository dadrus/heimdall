package provider

import (
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/rules/provider/filesystem"
)

// nolint
var Module = fx.Options(
	filesystem.Module,
)
