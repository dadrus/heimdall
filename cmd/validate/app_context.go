package validate

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keyholder"
	"github.com/dadrus/heimdall/internal/otel/metrics/certificate"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/watcher"
)

type appContext struct {
	w   watcher.Watcher
	khr keyholder.Registry
	co  certificate.Observer
	v   validation.Validator
	l   zerolog.Logger
	c   *config.Configuration
}

func (c *appContext) Watcher() watcher.Watcher                  { return c.w }
func (c *appContext) KeyHolderRegistry() keyholder.Registry     { return c.khr }
func (c *appContext) CertificateObserver() certificate.Observer { return c.co }
func (c *appContext) Validator() validation.Validator           { return c.v }
func (c *appContext) Logger() zerolog.Logger                    { return c.l }
func (c *appContext) Config() *config.Configuration             { return c.c }
