package admissioncontroller

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/fxlcm"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

// available here for test purposes
//
//nolint:gochecknoglobals
var listeningAddress = ":4458"

type AdmissionController interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

type noopController struct{}

func (noopController) Start(context.Context) error { return nil }
func (noopController) Stop(context.Context) error  { return nil }

func New(
	tlsConf *config.TLS,
	logger zerolog.Logger,
	authClass string,
	ruleFactory rule.Factory,
) AdmissionController {
	if tlsConf == nil {
		return noopController{}
	}

	return &fxlcm.LifecycleManager{
		ServiceName:    "Validating Admission Controller",
		ServiceAddress: listeningAddress,
		Server:         newService(listeningAddress, ruleFactory, authClass, logger),
		Logger:         logger,
		TLSConf:        tlsConf,
	}
}
