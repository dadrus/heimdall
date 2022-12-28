package rulesetparser

import (
	"errors"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/rules/rule"
)

func parseYAML(reader io.Reader) ([]rule.Configuration, error) {
	var (
		rawConfig []map[string]any
		rcs       []rule.Configuration
	)

	dec := yaml.NewDecoder(reader)
	if err := dec.Decode(&rawConfig); err != nil {
		if errors.Is(err, io.EOF) {
			return rcs, nil
		}

		return nil, err
	}

	err := rule.DecodeConfig(rawConfig, &rcs)

	return rcs, err
}
