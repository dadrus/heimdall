package parser

import (
	"github.com/a8m/envsubst"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func koanfFromYaml(configFile string) (*koanf.Koanf, error) {
	parser := koanf.New(".")

	buf, err := envsubst.ReadFile(configFile)
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to read yaml config from %s", configFile).CausedBy(err)
	}

	if err = parser.Load(rawbytes.Provider(buf), yaml.Parser()); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to load yaml config from %s", configFile).CausedBy(err)
	}

	return parser, nil
}
