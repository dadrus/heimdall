package ruleset

import (
	"errors"
	"io"

	"github.com/goccy/go-json"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/config"
)

func ParseYAML(reader io.Reader) ([]config.RuleConfig, error) {
	var rcs []config.RuleConfig

	dec := yaml.NewDecoder(reader)
	dec.KnownFields(true)

	if err := dec.Decode(&rcs); err != nil {
		if errors.Is(err, io.EOF) {
			return rcs, nil
		}

		return nil, err
	}

	return rcs, nil
}

func ParseJSON(reader io.Reader) ([]config.RuleConfig, error) {
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
