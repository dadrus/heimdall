package parser

// nolint: gochecknoglobals
var defaultOptions = opts{
	validate: func(configPath string) error { return nil },
}
