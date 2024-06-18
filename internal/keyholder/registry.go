package keyholder

import "github.com/go-jose/go-jose/v4"

type KeyHolder interface {
	Keys() []jose.JSONWebKey
}

//go:generate mockery --name Registry --structname RegistryMock

type Registry interface {
	AddKeyHolder(kh KeyHolder)
	Keys() []jose.JSONWebKey
}

func newRegistry() Registry {
	return &registry{}
}

type registry struct {
	keyHolders []KeyHolder
}

func (r *registry) AddKeyHolder(kh KeyHolder) {
	r.keyHolders = append(r.keyHolders, kh)
}

func (r *registry) Keys() []jose.JSONWebKey {
	var keys []jose.JSONWebKey

	for _, holder := range r.keyHolders {
		keys = append(keys, holder.Keys()...)
	}

	return keys
}
