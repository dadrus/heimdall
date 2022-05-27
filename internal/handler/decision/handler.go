package decision

import (
	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/fiber/middleware/xforwarded"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules"
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
	Logger          zerolog.Logger
	Signer          heimdall.JWTSigner
}

func newHandler(params handlerParams) (*Handler, error) {
	handler := &Handler{
		r: params.RulesRepository,
		s: params.Signer,
	}

	handler.registerRoutes(params.App.Group(""), params.Logger)

	return handler, nil
}

func (h *Handler) registerRoutes(router fiber.Router, logger zerolog.Logger) {
	logger.Debug().Msg("Registering decision api routes")

	router.All("/decisions/*", h.decisions)
}

func (h *Handler) decisions(c *fiber.Ctx) error {
	logger := zerolog.Ctx(c.UserContext())
	logger.Debug().Msg("Decision API called")

	reqURL := xforwarded.RequestURL(c.UserContext())

	rule, err := h.r.FindRule(reqURL)
	if err != nil {
		return errorchain.NewWithMessagef(heimdall.ErrInternal,
			"no applicable rule found for %s", reqURL.String()).CausedBy(err)
	}

	method := xforwarded.RequestMethod(c.UserContext())
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
