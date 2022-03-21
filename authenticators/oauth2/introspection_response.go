package oauth2

type Scopes []string

type IntrospectionResponse struct {
	Active          bool     `json:"active"`
	Scopes          Scopes   `json:"scope"`
	ClientId        string   `json:"client_id"`
	Username        string   `json:"username"`
	TokenType       string   `json:"token_type"`
	ExpiresAt       int64    `json:"exp"`
	NotBefore       int64    `json:"nbf"`
	IssuedAt        int64    `json:"iat"`
	SubjectId       string   `json:"sub"`
	Audience        []string `json:"aud"`
	Issuer          string   `json:"iss"`
	TokenIdentifier string   `json:"jti"`
}
