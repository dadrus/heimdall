package config

type PipelineObjectType string

const (
	POTNoop                PipelineObjectType = "noop"
	POTBasicAuth           PipelineObjectType = "basic_auth"
	POTAnonymous           PipelineObjectType = "anonymous"
	POTUnauthorized        PipelineObjectType = "unauthorized"
	POTOAuth2Introspection PipelineObjectType = "oauth2_introspection"
	POTJwt                 PipelineObjectType = "jwt"
	POTAllow               PipelineObjectType = "allow"
	POTDeny                PipelineObjectType = "deny"
	POTLocal               PipelineObjectType = "local"
	POTRemote              PipelineObjectType = "remote"
	POTDefault             PipelineObjectType = "default"
	POTGeneric             PipelineObjectType = "generic"
	POTHeader              PipelineObjectType = "header"
	POTCookie              PipelineObjectType = "cookie"
	POTRedirect            PipelineObjectType = "redirect"
	POTWWWAuthenticate     PipelineObjectType = "www_authenticate"
)

type PipelineObject struct {
	ID     string             `koanf:"id"`
	Type   PipelineObjectType `koanf:"type"`
	Config map[string]any     `koanf:"config"`
}
