package config

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"unicode"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog"
)

// nolint
var defaultDecodeHooks = []mapstructure.DecodeHookFunc{
	mapstructure.StringToTimeDurationHookFunc(),
	mapstructure.StringToSliceHookFunc(","),
	logLevelDecodeHookFunc,
	logFormatDecodeHookFunc,
}

// LoadConfig loads configuration into the given struct. This will take into account the following
// sources:
//
// - the given struct
// - the .env file given as "optionalConfigFile" if this argument is not nil/empty
// - a .env file in root if no file was given. This is optional
// - Overrides from Environment
//
// Per convention all fields in the struct must have lowercase "koanf" tags.
// Environment Variables will be automatically converted to lowercase. The underscore "_" serves as
// hierarchy-separator ("FOO_BAR" matches the field "bar" in the nested strut "foo".)
//
// Type Conversions for standard types are present as well as for slices and durations.
func LoadConfig(config interface{}, configFile string) error {
	return LoadConfigWithDecoder(config, configFile, nil)
}

// LoadConfigWithDecoder works like "LoadConfig", but allows to use an additional DecodeHook to allow
// conversion from string values to custom types.
func LoadConfigWithDecoder(config interface{}, optConfFile string, addDecodeHook mapstructure.DecodeHookFunc) error {
	configFile := optConfFile
	if len(configFile) == 0 {
		configFile = "configs/config.yaml"
	}

	parser, err := koanfFromStruct(config)
	if err != nil {
		return err
	}

	loadAndMergeConfig := func(loadConfig func() (*koanf.Koanf, error)) error {
		c, err := loadConfig()
		if err != nil {
			return err
		}

		return parser.Merge(c)
	}

	if _, err := os.Stat(configFile); err == nil {
		if err := loadAndMergeConfig(func() (*koanf.Koanf, error) { return koanfFromYaml(configFile) }); err != nil {
			return err
		}
	}

	if err := loadAndMergeConfig(koanfFromEnv); err != nil {
		return err
	}

	hooks := defaultDecodeHooks
	if addDecodeHook != nil {
		hooks = append(hooks, addDecodeHook)
	}

	return parser.UnmarshalWithConf("", config, koanf.UnmarshalConf{
		Tag: "koanf",
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook:       mapstructure.ComposeDecodeHookFunc(hooks...),
			Metadata:         nil,
			Result:           config,
			WeaklyTypedInput: true,
		},
	})
}

func koanfFromYaml(configFile string) (*koanf.Koanf, error) {
	parser := koanf.New(".")

	err := parser.Load(file.Provider(configFile), yaml.Parser())
	if err != nil {
		return nil, fmt.Errorf("failed to read yaml config from %s: %w", configFile, err)
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

func koanfFromStruct(s interface{}) (*koanf.Koanf, error) {
	parser := koanf.New(".")

	err := parser.Load(structs.Provider(s, "koanf"), nil)
	if err != nil {
		return nil, err
	}

	var keys = parser.Keys()
	// Assert all Keys are lowercase
	for i := 0; i < len(keys); i++ {
		if !isLower(keys[i]) {
			return nil,
				fmt.Errorf("field %s in the Config Struct does not have lowercase key, use the `koanf` tag", keys[i])
		}
	}

	return parser, nil
}

func koanfFromEnv() (*koanf.Koanf, error) {
	var parser = koanf.New(".")

	err := parser.Load(env.Provider("", ".", strings.ToLower), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Environment Variables to Config: %w", err)
	}

	return transformEnvFormat(parser)
}

func transformEnvFormat(parser *koanf.Koanf) (*koanf.Koanf, error) {
	flattened := parser.All()
	exploded := make(map[string]interface{})

	for key, value := range flattened {
		keys := expandSlices(strings.Split(key, "_"))
		for _, newKey := range keys {
			exploded[strings.ToLower(newKey)] = value
		}
	}

	parser = koanf.New(".")

	err := parser.Load(confmap.Provider(exploded, "."), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse flattened Environment Variables to Config: %w", err)
	}

	return parser, nil
}

func expandSlices(parts []string) []string {
	if len(parts) == 1 {
		return parts
	}

	next := expandSlices(parts[1:])
	result := make([]string, 0, len(next)*2)

	for _, k := range next {
		result = append(result, parts[0]+"."+k)
		result = append(result, parts[0]+"_"+k)
	}

	return result
}

// Decode zeroLog LogLevels from strings.
func logLevelDecodeHookFunc(from reflect.Type, to reflect.Type, val interface{}) (interface{}, error) {
	var level zerolog.Level

	if from.Kind() != reflect.String {
		return val, nil
	}

	dect := reflect.ValueOf(&level).Elem().Type()
	if !dect.AssignableTo(to) {
		return val, nil
	}

	switch val {
	case "panic":
		level = zerolog.PanicLevel
	case "fatal":
		level = zerolog.FatalLevel
	case "error":
		level = zerolog.ErrorLevel
	case "warn":
		level = zerolog.WarnLevel
	case "debug":
		level = zerolog.DebugLevel
	default:
		level = zerolog.InfoLevel
	}

	return level, nil
}
