package config

import "encoding/json"

type PipelineObjectReference struct {
	ID     string
	Config json.RawMessage
}
