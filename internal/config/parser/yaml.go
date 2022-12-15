package parser

import (
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func koanfFromYaml(configFile string) (*koanf.Koanf, error) {
	parser := koanf.New(".")

	if err := parser.Load(file.Provider(configFile), yaml.Parser()); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to load yaml config from %s", configFile).CausedBy(err)
	}

	return parser, nil
}
