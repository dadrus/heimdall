package mutators

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type CompositeMutator []handler.Mutator

func (cm CompositeMutator) Mutate(c context.Context, sc *heimdall.SubjectContext) error {
	var err error
	for _, m := range cm {
		err = m.Mutate(c, sc)
		if err != nil {
			// try next
			continue
		} else {
			return nil
		}
	}
	return err
}

func (cm CompositeMutator) WithConfig(_ json.RawMessage) (handler.Mutator, error) {
	return nil, errors.New("reconfiguration not allowed")
}
