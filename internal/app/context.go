package app

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keyholder"
	"github.com/dadrus/heimdall/internal/otel/metrics/certificate"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/watcher"
)

//go:generate mockery --name Context --structname ContextMock  --inpackage

type Context interface {
	Watcher() watcher.Watcher
	KeyHolderRegistry() keyholder.Registry
	CertificateObserver() certificate.Observer
	Validator() validation.Validator
	Logger() zerolog.Logger
	Config() *config.Configuration
}
