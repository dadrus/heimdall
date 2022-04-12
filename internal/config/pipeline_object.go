package config

type PipelineObjectType string

const (
	POTNoop                PipelineObjectType = "noop"
	POTAnonymous           PipelineObjectType = "anonymous"
	POTUnauthorized        PipelineObjectType = "unauthorized"
	POTAuthenticationData  PipelineObjectType = "authentication_data"
	POTOAuth2Introspection PipelineObjectType = "oauth2_introspection"
	POTJwt                 PipelineObjectType = "jwt"
	POTAllow               PipelineObjectType = "allow"
	POTDeny                PipelineObjectType = "deny"
	POTRemote              PipelineObjectType = "remote"
	POTDefault             PipelineObjectType = "default"
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
