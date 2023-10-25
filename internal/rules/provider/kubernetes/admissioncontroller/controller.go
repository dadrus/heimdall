package admissioncontroller

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/handler/fxlcm"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

type AdmissionController interface {
	Start(context.Context) error
	Stop(context.Context) error
}

type noopController struct{}

func (noopController) Start(context.Context) error { return nil }
func (noopController) Stop(context.Context) error  { return nil }

func New(
	conf *Config,
	logger zerolog.Logger,
	authClass string,
	ruleFactory rule.Factory,
) AdmissionController {
	if !conf.Enabled {
		return noopController{}
	}

	return &fxlcm.LifecycleManager{
		ServiceName:    "Validating Admission Controller",
		ServiceAddress: conf.Address(),
		Server:         newService(conf, ruleFactory, authClass, logger),
		Logger:         logger,
		TLSConf:        &conf.TLS,
	}
}
