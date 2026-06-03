package secrets

import (
	"context"
	"maps"
	"sync"
)

type bindingProvider interface {
	secretBinding(
		reference scopedReference,
	) (*binding[Secret], bindingKey, error)

	secretSetBinding(
		reference scopedReference,
	) (*binding[[]Secret], bindingKey, error)

	credentialsBinding(
		reference scopedReference,
	) (*binding[Credentials], bindingKey, error)

	certificateBundleBinding(
		reference scopedReference,
	) (*binding[CertificateBundle], bindingKey, error)

	releaseBinding(key bindingKey, count int)
}

type scope struct {
	bindings   bindingProvider
	refFactory referenceFactory

	id        string
	namespace string

	mu        sync.Mutex
	leases    map[bindingKey]int
	cleanups  []func()
	readiness []func(context.Context) error

	closed bool
}

func newScope(
	bindings bindingProvider,
	opts ...ScopeOption,
) *scope {
	scp := &scope{
		bindings:   bindings,
		refFactory: internalRef,
		leases:     make(map[bindingKey]int),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(scp)
		}
	}

	return scp
}

func (s *scope) Secret(ref Reference) (SecretHandle, error) {
	bdg, key, err := s.bindings.secretBinding(s.refFactory(ref))
	if err != nil {
		return nil, err
	}

	if !s.trackLease(key) {
		s.bindings.releaseBinding(key, 1)

		return nil, ErrResolverScopeClosed
	}

	return newHandle[Secret](bdg, s), nil
}

func (s *scope) SecretSet(ref Reference) (SecretSetHandle, error) {
	bdg, key, err := s.bindings.secretSetBinding(s.refFactory(ref))
	if err != nil {
		return nil, err
	}

	if !s.trackLease(key) {
		s.bindings.releaseBinding(key, 1)

		return nil, ErrResolverScopeClosed
	}

	return newHandle[[]Secret](bdg, s), nil
}

func (s *scope) Credentials(ref Reference) (CredentialsHandle, error) {
	bdg, key, err := s.bindings.credentialsBinding(s.refFactory(ref))
	if err != nil {
		return nil, err
	}

	if !s.trackLease(key) {
		s.bindings.releaseBinding(key, 1)

		return nil, ErrResolverScopeClosed
	}

	return newHandle[Credentials](bdg, s), nil
}

func (s *scope) CertificateBundle(ref Reference) (CertificateBundleHandle, error) {
	bdg, key, err := s.bindings.certificateBundleBinding(s.refFactory(ref))
	if err != nil {
		return nil, err
	}

	if !s.trackLease(key) {
		s.bindings.releaseBinding(key, 1)

		return nil, ErrResolverScopeClosed
	}

	return newHandle[CertificateBundle](bdg, s), nil
}

func (s *scope) Release() {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()

		return
	}

	leases := maps.Clone(s.leases)
	clear(s.leases)

	cleanups := append([]func(){}, s.cleanups...)
	s.cleanups = nil
	s.closed = true
	s.readiness = nil

	s.mu.Unlock()

	for _, cleanup := range cleanups {
		cleanup()
	}

	for key, count := range leases {
		s.bindings.releaseBinding(key, count)
	}
}

func (s *scope) AwaitReady(ctx context.Context) error {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()

		return ErrResolverScopeClosed
	}

	waiters := append([]func(context.Context) error(nil), s.readiness...)

	s.mu.Unlock()

	for _, await := range waiters {
		if err := await(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (s *scope) trackLease(key bindingKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return false
	}

	s.leases[key]++

	return true
}

func (s *scope) registerCleanup(cleanup func()) {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()
		cleanup()

		return
	}

	s.cleanups = append(s.cleanups, cleanup)
	s.mu.Unlock()
}

func (s *scope) registerReadiness(await func(context.Context) error) {
	if await == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	s.readiness = append(s.readiness, await)
}

var (
	_ Resolver       = (*scope)(nil)
	_ ScopedResolver = (*scope)(nil)
	_ handleOwner    = (*scope)(nil)
)
