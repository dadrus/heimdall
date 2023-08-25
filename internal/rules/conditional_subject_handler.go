package rules

import (
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type conditionalSubjectHandler struct {
	h subjectHandler
	c executionCondition
}

func (h *conditionalSubjectHandler) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())

	logger.Debug().Str("_id", h.h.ID()).Msg("Checking execution condition")

	if logger.GetLevel() == zerolog.TraceLevel {
		dump, err := json.Marshal(sub)
		if err != nil {
			logger.Trace().Err(err).Msg("Failed to dump subject")
		} else {
			logger.Trace().Msg("Subject: \n" + stringx.ToString(dump))
		}
	}

	if canExecute, err := h.c.CanExecute(ctx, sub); err != nil {
		return err
	} else if canExecute {
		return h.h.Execute(ctx, sub)
	}

	logger.Debug().Str("_id", h.h.ID()).Msg("Execution skipped")

	return nil
}

func (h *conditionalSubjectHandler) ID() string { return h.h.ID() }

func (h *conditionalSubjectHandler) ContinueOnError() bool { return h.h.ContinueOnError() }
