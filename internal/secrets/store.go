package secrets

import (
	"context"
	"sync"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type store struct {
	manager    Manager
	refFactory ReferenceFactory

	mu        sync.RWMutex
	informers map[Reference]*SecretInformer[string]
}

func NewStore(
	manager Manager,
	refFactory ReferenceFactory,
) (Store, error) {
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

	return &store{
		manager:    manager,
		refFactory: refFactory,
		informers:  make(map[Reference]*SecretInformer[string]),
	}, nil
}

func (s *store) RegisterSecret(ref Reference) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.informers[ref]; ok {
		return nil
	}

	inf := &SecretInformer[string]{
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

func (s *store) GetSecret(ref Reference) (string, error) {
	s.mu.RLock()
	inf := s.informers[ref]
	s.mu.RUnlock()

	if inf == nil {
		return "", ErrSecretNotFound
	}

	value, ok := inf.Get()
	if !ok {
		return "", ErrSecretNotFound
	}

	return value, nil
}

func (s *store) CleanUp() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, inf := range s.informers {
		inf.Stop()
	}

	clear(s.informers)
}

func stringSecretValue(secret Secret) (string, error) {
	stringSecret, ok := secret.(StringSecret)
	if !ok {
		return "", ErrSecretKindMismatch
	}

	return stringSecret.Value(), nil
}
