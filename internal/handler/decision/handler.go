package decision

import (
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
}

type handlerArgs struct {
	fx.In

	App             *fiber.App `name:"decision"`
	RulesRepository rules.Repository
	KeyStore        keystore.KeyStore
	Config          *config.Configuration
	Logger          zerolog.Logger
}

func newHandler(args handlerArgs) (*Handler, error) {
	jwtSigner, err := signer.NewJWTSigner(args.KeyStore, args.Config.Signer, args.Logger)
	if err != nil {
		return nil, err
	}

	handler := &Handler{
		r: args.RulesRepository,
		s: jwtSigner,
	}

	handler.registerRoutes(args.App.Group("/"), args.Logger)

	return handler, nil
}

func (h *Handler) registerRoutes(router fiber.Router, logger zerolog.Logger) {
	logger.Debug().Msg("Registering decision service routes")

	router.All("/*", fiberxforwarded.New(), h.decisions)
}

func (h *Handler) decisions(c *fiber.Ctx) error {
	logger := zerolog.Ctx(c.UserContext())
	logger.Debug().Msg("Decision endpoint called")

	reqURL := fiberxforwarded.RequestURL(c.UserContext())
	method := fiberxforwarded.RequestMethod(c.UserContext())

	rule, err := h.r.FindRule(reqURL)
	if err != nil {
		return err
	}

	if !rule.MatchesMethod(method) {
		return errorchain.NewWithMessagef(heimdall.ErrMethodNotAllowed,
			"rule doesn't match %s method", method)
	}

	reqCtx := requestcontext.New(c, method, reqURL, h.s)

	_, err = rule.Execute(reqCtx)
	if err != nil {
		return err
	}

	logger.Debug().Msg("Finalizing request")

	return reqCtx.Finalize()
}
