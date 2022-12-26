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
	"github.com/dadrus/heimdall/internal/rules"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type Handler struct {
	r rules.Repository
	s heimdall.JWTSigner
	t time.Duration
}

type handlerArgs struct {
	fx.In

	App             *fiber.App `name:"proxy"`
	RulesRepository rules.Repository
	Config          *config.Configuration
	Signer          heimdall.JWTSigner
	Logger          zerolog.Logger
}

func newHandler(args handlerArgs) (*Handler, error) {
	handler := &Handler{
		r: args.RulesRepository,
		s: args.Signer,
		t: args.Config.Serve.Proxy.Timeout.Read,
	}

	handler.registerRoutes(args.App.Group("/"), args.Logger)

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
