package admissioncontroller

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/fxlcm"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

type AdmissionController interface {
	Start(context.Context) error
	Stop(context.Context) error
}

func New(
	tlsConf *config.TLS,
	logger zerolog.Logger,
	authClass string,
	ruleFactory rule.Factory,
) AdmissionController {
	listeningAddress := ":8433"

	return &fxlcm.LifecycleManager{
		ServiceName:    "Validating Admission Controller",
		ServiceAddress: listeningAddress,
		Server:         newService(listeningAddress, ruleFactory, authClass, logger),
		Logger:         logger,
		TLSConf:        tlsConf,
	}
}
