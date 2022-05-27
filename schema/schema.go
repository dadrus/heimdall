package schema

import _ "embed"

// ConfigSchema defines a JSON schema for configuration validation purposes
//go:embed config.schema.json
var ConfigSchema []byte
