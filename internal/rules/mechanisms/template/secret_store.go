package template

import (
	"context"
	"sync"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/secrets/informer"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type SecretReference struct {
	Source   string
	Selector string
}

type SecretStore interface {
	RegisterSecret(ref SecretReference) error
	GetSecret(ref SecretReference) (string, error)
	CleanUp()
}

type SecretReferenceFactory func(source, selector string) secrets.Reference

type secretStore struct {
	manager    secrets.Manager
	refFactory SecretReferenceFactory

	mu        sync.RWMutex
	informers map[SecretReference]*informer.SecretInformer[string]
}

func NewSecretStore(
	manager secrets.Manager,
	refFactory SecretReferenceFactory,
) (SecretStore, error) {
	if manager == nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"secret manager is not configured",
		)
	}

	if refFactory == nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"secret reference factory is not configured",
		)
	}

	return &secretStore{
		manager:    manager,
		refFactory: refFactory,
		informers:  make(map[SecretReference]*informer.SecretInformer[string]),
	}, nil
}

func (s *secretStore) RegisterSecret(ref SecretReference) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.informers[ref]; ok {
		return nil
	}

	inf := &informer.SecretInformer[string]{
		Manager:   s.manager,
		Reference: s.refFactory(ref.Source, ref.Selector),
		Converter: stringSecretValue,
	}

	if err := inf.Start(context.Background()); err != nil { //nolint:contextcheck
		return err
	}

	s.informers[ref] = inf

	return nil
}

func (s *secretStore) GetSecret(ref SecretReference) (string, error) {
	s.mu.RLock()
	inf := s.informers[ref]
	s.mu.RUnlock()

	if inf == nil {
		return "", secrets.ErrSecretNotFound
	}

	value, ok := inf.Get()
	if !ok {
		return "", secrets.ErrSecretNotFound
	}

	return value, nil
}

func (s *secretStore) CleanUp() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, inf := range s.informers {
		inf.Stop()
	}

	clear(s.informers)
}

func stringSecretValue(secret secrets.Secret) (string, error) {
	stringSecret, ok := secret.(secrets.StringSecret)
	if !ok {
		return "", secrets.ErrSecretKindMismatch
	}

	return stringSecret.Value(), nil
}
