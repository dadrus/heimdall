package config

import (
	"fmt"
	"os"
	"time"

	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/config/parser"
)

const (
	defaultReadTimeout  = time.Second * 5
	defaultWriteTimeout = time.Second * 10
	defaultIdleTimeout  = time.Second * 120

	defaultProxyPort       = 4455
	defaultDecisionAPIPort = 4456
	defaultPrometheusPort  = 9000
)

type Configuration struct {
	Serve    ServeConfig    `koanf:"serve"`
	Log      LoggingConfig  `koanf:"log"`
	Tracing  TracingConfig  `koanf:"tracing"`
	Metrics  MetricsConfig  `koanf:"metrics"`
	Signer   SignerConfig   `koanf:"signer"`
	Cache    CacheConfig    `koanf:"cache"`
	Pipeline PipelineConfig `koanf:"pipeline"`
	Rules    RulesConfig    `koanf:"rules"`
}

func NewConfiguration(configFile string) (Configuration, error) {
	// copy defaults
	result := defaultConfig

	opts := []parser.Option{
		parser.WithConfigFile(configFile),
		parser.WithDefaultConfigFilename("heimdall.yaml"),
		parser.WithConfigValidator(ValidateConfig),
		parser.WithDecodeHookFunc(mapstructure.StringToTimeDurationHookFunc()),
		parser.WithDecodeHookFunc(mapstructure.StringToSliceHookFunc(",")),
		parser.WithDecodeHookFunc(logLevelDecodeHookFunc),
		parser.WithDecodeHookFunc(logFormatDecodeHookFunc),
	}

	// if no config file provided, the lookup order for the heimdall.yaml file
	// is:
	//
	// 1. current working directory
	// 2. $HOME/.config
	// 3. /etc/heimdall/
	pwd, err := os.Getwd()
	if err == nil {
		opts = append(opts, parser.WithConfigLookupDir(pwd))
	}

	homeDir, err := os.UserHomeDir()
	if err == nil {
		opts = append(opts, parser.WithConfigLookupDir(fmt.Sprintf("%s/.config/", homeDir)))
	}

	opts = append(opts, parser.WithConfigLookupDir("/etc/heimdall/"))

	err = parser.New(opts...).Load(&result)

	return result, err
}
