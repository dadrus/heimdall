package rules

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type compositeSubjectHandler []subjectHandler

func (cm compositeSubjectHandler) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())

	for _, m := range cm {
		err := m.Execute(ctx, sub)
		if err != nil {
			logger.Debug().Err(err).Msg("Pipeline step execution failed")

			return err
		}
	}

	return nil
}
