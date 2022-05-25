package heimdall

type JWTSigner interface {
	Name() string
	KeyID() string
	Algorithm() string
	Sign(claims map[string]any) (string, error)
}
