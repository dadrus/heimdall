package rulesetparser

import (
	"errors"
	"io"

	"github.com/goccy/go-json"

	"github.com/dadrus/heimdall/internal/config"
)

func parseJSON(reader io.Reader) ([]config.RuleConfig, error) {
	var rcs []config.RuleConfig

	dec := json.NewDecoder(reader)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&rcs); err != nil {
		if errors.Is(err, io.EOF) {
			return rcs, nil
		}

		return nil, err
	}

	return rcs, nil
}
