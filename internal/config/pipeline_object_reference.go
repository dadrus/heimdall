package config

import "encoding/json"

type PipelineObjectReference struct {
	Id     string
	Config json.RawMessage
}
