package provider

import (
	"github.com/rs/zerolog"

	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
)

func registerDockerProvider(_ fx.Lifecycle, _ zerolog.Logger, _ config.Configuration, _ RuleSetChangedEventQueue) {
	// TODO: implement me
}
