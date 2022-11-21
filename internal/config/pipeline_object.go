package config

type PipelineHandlerType string

const (
	POTNoop                PipelineHandlerType = "noop"
	POTBasicAuth           PipelineHandlerType = "basic_auth"
	POTAnonymous           PipelineHandlerType = "anonymous"
	POTUnauthorized        PipelineHandlerType = "unauthorized"
	POTOAuth2Introspection PipelineHandlerType = "oauth2_introspection"
	POTJwt                 PipelineHandlerType = "jwt"
	POTAllow               PipelineHandlerType = "allow"
	POTDeny                PipelineHandlerType = "deny"
	POTLocal               PipelineHandlerType = "local"
	POTRemote              PipelineHandlerType = "remote"
	POTDefault             PipelineHandlerType = "default"
	POTGeneric             PipelineHandlerType = "generic"
	POTHeader              PipelineHandlerType = "header"
	POTCookie              PipelineHandlerType = "cookie"
	POTRedirect            PipelineHandlerType = "redirect"
	POTWWWAuthenticate     PipelineHandlerType = "www_authenticate"
)

func (p PipelineHandlerType) String() string { return string(p) }

type PipelineHandler struct {
	ID     string              `koanf:"id"`
	Type   PipelineHandlerType `koanf:"type,string"`
	Config map[string]any      `koanf:"config"`
}
