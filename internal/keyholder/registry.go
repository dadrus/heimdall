package keyholder

import "github.com/go-jose/go-jose/v4"

//go:generate mockery --name Registry --structname RegistryMock

type Registry interface {
	Add(keyHolder KeyHolder)
	Keys() []jose.JSONWebKey
}

func newRegistry() Registry {
	return &registry{}
}

type registry struct {
	kh []KeyHolder
}

func (r *registry) Add(keyHolder KeyHolder) {
	r.kh = append(r.kh, keyHolder)
}

func (r *registry) Keys() []jose.JSONWebKey {
	var keys []jose.JSONWebKey

	for _, holder := range r.kh {
		keys = append(keys, holder.Keys()...)
	}

	return keys
}
