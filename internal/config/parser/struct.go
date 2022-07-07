package parser

import (
	"unicode"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/providers/structs"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func koanfFromStruct(conf any) (*koanf.Koanf, error) {
	parser := koanf.New(".")

	err := parser.Load(structs.Provider(conf, "koanf"), nil)
	if err != nil {
		return nil, err
	}

	keys := parser.Keys()
	// Assert all keys are lowercase
	for i := 0; i < len(keys); i++ {
		if !isLower(keys[i]) {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"field %s does not have lowercase key, use the `koanf` tag", keys[i])
		}
	}

	return parser, nil
}

func isLower(s string) bool {
	for _, r := range s {
		if !unicode.IsLower(r) && unicode.IsLetter(r) {
			return false
		}
	}

	return true
}
