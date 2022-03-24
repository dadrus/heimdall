package config

import "encoding/json"

type PipelineObjectType string

const (
	Noop                PipelineObjectType = "noop"
	Anonymous           PipelineObjectType = "anonymous"
	Unauthorized        PipelineObjectType = "unauthorized"
	AuthenticationData  PipelineObjectType = "authentication_data"
	OAuth2Introspection PipelineObjectType = "oauth2_introspection"
	Jwt                 PipelineObjectType = "jwt"
	Allow               PipelineObjectType = "allow"
	Deny                PipelineObjectType = "deny"
	Remote              PipelineObjectType = "remote"
	Default             PipelineObjectType = "default"
	Header              PipelineObjectType = "header"
	Json                PipelineObjectType = "json"
	Redirect            PipelineObjectType = "redirect"
)

type PipelineObject struct {
	Id     string             `koanf:"id"`
	Type   PipelineObjectType `koanf:"type"`
	Config json.RawMessage    `koanf:"config"`
}
