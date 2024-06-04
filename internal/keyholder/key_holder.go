package keyholder

import "github.com/go-jose/go-jose/v4"

type KeyHolder interface {
	Keys() []jose.JSONWebKey
}
