package decision

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	fiberauditor "github.com/dadrus/heimdall/internal/fiber/middleware/auditor"
	fiberxforwarded "github.com/dadrus/heimdall/internal/fiber/middleware/xforwarded"
	"github.com/dadrus/heimdall/internal/handler/health"
	"github.com/dadrus/heimdall/internal/handler/jwks"
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
}

type handlerParams struct {
	fx.In

	App             *fiber.App `name:"api"`
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
	}

	router := params.App.Group("/")

	handler.registerRoutes(router, params.Logger)
	health.RegisterRoutes(router, params.Logger)
	jwks.RegisterRoutes(router, params.Logger, params.KeyStore)

	return handler, nil
}

func (h *Handler) registerRoutes(router fiber.Router, logger zerolog.Logger) {
	logger.Debug().Msg("Registering decision api routes")

	router.All("/decisions/*", fiberxforwarded.New(), fiberauditor.New(), h.decisions)
}

func (h *Handler) decisions(c *fiber.Ctx) error {
	logger := zerolog.Ctx(c.UserContext())
	logger.Debug().Msg("Decision API called")

	reqURL := fiberxforwarded.RequestURL(c.UserContext())

	rule, err := h.r.FindRule(reqURL)
	if err != nil {
		return errorchain.NewWithMessagef(heimdall.ErrInternal,
			"no applicable rule found for %s", reqURL.String()).CausedBy(err)
	}

	method := fiberxforwarded.RequestMethod(c.UserContext())
	if !rule.MatchesMethod(method) {
		return errorchain.NewWithMessagef(heimdall.ErrMethodNotAllowed,
			"rule doesn't match %s method", method)
	}

	reqCtx := requestcontext.New(c, reqURL, h.s)
	if err = rule.Execute(reqCtx); err != nil {
		return err
	}

	logger.Debug().Msg("Finalizing request")

	if err = reqCtx.Finalize(); err != nil {
		return err
	}

	c.Status(fiber.StatusAccepted)

	return nil
}
