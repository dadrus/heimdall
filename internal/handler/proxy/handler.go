package proxy

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	fiberxforwarded "github.com/dadrus/heimdall/internal/fiber/middleware/xfmphu"
	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/rules"
	"github.com/dadrus/heimdall/internal/signer"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type Handler struct {
	r rules.Repository
	s heimdall.JWTSigner
	t time.Duration
}

type handlerParams struct {
	fx.In

	App             *fiber.App `name:"proxy"`
	RulesRepository rules.Repository
	KeyStore        keystore.KeyStore
	Config          config.Configuration
	Logger          zerolog.Logger
}

func newHandler(params handlerParams) (*Handler, error) {
	jwtSigner, err := signer.NewJWTSigner(params.KeyStore, params.Config.Signer, params.Logger)
	if err != nil {
		return nil, err
	}

	handler := &Handler{
		r: params.RulesRepository,
		s: jwtSigner,
		t: params.Config.Serve.Proxy.Timeout.Read,
	}

	router := params.App.Group("/")

	handler.registerRoutes(router, params.Logger)

	return handler, nil
}

func (h *Handler) registerRoutes(router fiber.Router, logger zerolog.Logger) {
	logger.Debug().Msg("Registering Proxy service routes")

	router.All("/*", fiberxforwarded.New(), h.proxy)
}

func (h *Handler) proxy(c *fiber.Ctx) error {
	logger := zerolog.Ctx(c.UserContext())
	logger.Debug().Msg("Proxy endpoint called")

	reqURL := fiberxforwarded.RequestURL(c.UserContext())
	method := fiberxforwarded.RequestMethod(c.UserContext())

	rule, err := h.r.FindRule(reqURL)
	if err != nil {
		return err
	}

	if !rule.MatchesMethod(method) {
		return errorchain.NewWithMessagef(heimdall.ErrMethodNotAllowed,
			"rule (id=%s, src=%s) doesn't match %s method", rule.ID(), rule.SrcID(), method)
	}

	reqCtx := requestcontext.New(c, method, reqURL, h.s)

	upstreamURL, err := rule.Execute(reqCtx)
	if err != nil {
		return err
	}

	logger.Debug().Msg("Finalizing request")

	return reqCtx.FinalizeAndForward(upstreamURL, h.t)
}
