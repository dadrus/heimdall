package mutators

import (
	"crypto"

	"github.com/stretchr/testify/mock"
	"gopkg.in/square/go-jose.v2"
)

type MockJWTSigner struct {
	mock.Mock
}

func (m *MockJWTSigner) Name() string {
	args := m.Called()

	return args.String(0)
}

func (m *MockJWTSigner) KeyID() string {
	args := m.Called()

	return args.String(0)
}

func (m *MockJWTSigner) Algorithm() jose.SignatureAlgorithm {
	args := m.Called()

	return jose.SignatureAlgorithm(args.String(0))
}

func (m *MockJWTSigner) Key() crypto.Signer {
	args := m.Called()
	val := args.Get(0)

	res, ok := val.(crypto.Signer)
	if !ok {
		panic("crypto.Signer expected")
	}

	return res
}
