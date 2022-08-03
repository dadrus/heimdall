package rules

import (
	"errors"

	"github.com/dadrus/heimdall/internal/fiber/middleware/accesslog"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type compositeSubjectCreator []subjectCreator

func (ca compositeSubjectCreator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	acl := accesslog.Ctx(ctx.AppContext())

	var (
		sub *subject.Subject
		err error
	)

	for idx, a := range ca {
		sub, err = a.Execute(ctx)
		if err != nil {
			logger.Info().Err(err).Msg("Pipeline step execution failed")

			if (errors.Is(err, heimdall.ErrArgument) || a.IsFallbackOnErrorAllowed()) && idx < len(ca) {
				logger.Info().Msg("Falling back to next configured one.")

				continue
			}

			break
		}

		acl.Subject = sub.ID

		return sub, nil
	}

	return nil, err
}
