package rules

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type compositeSubjectCreator []subjectCreator

func (ca compositeSubjectCreator) Execute(ctx heimdall.Context) (sub *subject.Subject, err error) {
	logger := zerolog.Ctx(ctx.AppContext())

	for _, a := range ca {
		sub, err = a.Execute(ctx)
		if err == nil {
			return sub, nil
		}

		logger.Info().Err(err).Msg("Pipeline step execution failed")
	}

	return nil, err
}
