package oauth2

import (
	"errors"
	"net/http"
	"strings"

	"github.com/dadrus/heimdall/internal/x/httpx"
)

var (
	ErrAssertion  = errors.New("assertion error")
	ErrScopeMatch = errors.New("scope matching error")
	ErrDPoPProof  = errors.New("DPoP proof error")
	ErrDPoPNonce  = errors.New("DPoP nonce error")

	ErrTokenNotActive = errors.New("token is not active")
)

type oauth2ChallengeError struct {
	message string
	scheme  TokenScheme
}

func (e *oauth2ChallengeError) Error() string {
	if e.message == "" {
		return "oauth2 assertion error"
	}

	return "oauth2 assertion error: " + e.message
}

func (e *oauth2ChallengeError) commonParams(
	policy ChallengePolicy,
	errorCode string,
) []httpx.Option {
	opts := []httpx.Option{
		httpx.WithPrefix(string(e.scheme)),
		httpx.WithKeyValue("realm", policy.Realm),
		httpx.WithKeyValue("error", errorCode),
	}

	if policy.ErrorURI != "" {
		opts = append(opts, httpx.WithKeyValue("error_uri", policy.ErrorURI))
	}

	if policy.IncludeErrorDetails && e.message != "" {
		opts = append(opts, httpx.WithKeyValue("error_description", e.message))
	}

	return opts
}

type ScopeMismatchError struct {
	required []string
	missing  []string
	cause    error
}

func NewScopeMismatchError(required, missing []string) *ScopeMismatchError {
	return &ScopeMismatchError{
		required: required,
		missing:  missing,
	}
}

func (e *ScopeMismatchError) Error() string            { return "scope matching error" }
func (e *ScopeMismatchError) Unwrap() error            { return e.cause }
func (e *ScopeMismatchError) RequiredScopes() []string { return e.required }
func (e *ScopeMismatchError) MissingScopes() []string  { return e.missing }

type InvalidRequestError struct {
	oauth2ChallengeError
}

func NewInvalidRequestError(scheme TokenScheme, message string) *InvalidRequestError {
	return &InvalidRequestError{
		oauth2ChallengeError: oauth2ChallengeError{
			message: message,
			scheme:  scheme,
		},
	}
}

func (e *InvalidRequestError) Challenge(policy ChallengePolicy) (*Challenge, error) {
	opts := e.commonParams(policy, "invalid_request")

	header := make(http.Header)
	header.Add("WWW-Authenticate", httpx.NewHeader(opts...))

	return &Challenge{
		StatusCode: http.StatusBadRequest,
		Headers:    header,
	}, nil
}

type InvalidTokenError struct {
	oauth2ChallengeError
}

func NewInvalidTokenError(scheme TokenScheme, message string) *InvalidTokenError {
	return &InvalidTokenError{
		oauth2ChallengeError: oauth2ChallengeError{
			message: message,
			scheme:  scheme,
		},
	}
}

func (e *InvalidTokenError) Challenge(policy ChallengePolicy) (*Challenge, error) {
	opts := e.commonParams(policy, "invalid_token")

	header := make(http.Header)
	header.Add("WWW-Authenticate", httpx.NewHeader(opts...))

	return &Challenge{
		StatusCode: http.StatusUnauthorized,
		Headers:    header,
	}, nil
}

type InsufficientScopeError struct {
	oauth2ChallengeError

	requiredScopes []string
}

func NewInsufficientScopeError(
	scheme TokenScheme,
	message string,
	requiredScopes []string,
) *InsufficientScopeError {
	return &InsufficientScopeError{
		oauth2ChallengeError: oauth2ChallengeError{
			message: message,
			scheme:  scheme,
		},
		requiredScopes: requiredScopes,
	}
}

func (e *InsufficientScopeError) Challenge(policy ChallengePolicy) (*Challenge, error) {
	opts := e.commonParams(policy, "insufficient_scope")

	if policy.IncludeRequiredScopes && len(e.requiredScopes) != 0 {
		opts = append(opts, httpx.WithKeyValue(
			"scope",
			strings.Join(e.requiredScopes, " "),
		))
	}

	header := make(http.Header)
	header.Add("WWW-Authenticate", httpx.NewHeader(opts...))

	return &Challenge{
		StatusCode: http.StatusForbidden,
		Headers:    header,
	}, nil
}

type InvalidDPoPProofError struct {
	oauth2ChallengeError
}

func NewInvalidDPoPProofError(message string) *InvalidDPoPProofError {
	return &InvalidDPoPProofError{
		oauth2ChallengeError: oauth2ChallengeError{
			message: message,
			scheme:  SchemeDPoP,
		},
	}
}

func (e *InvalidDPoPProofError) Challenge(policy ChallengePolicy) (*Challenge, error) {
	opts := e.commonParams(policy, "invalid_dpop_proof")

	if len(policy.DPoPAlgorithms) != 0 {
		opts = append(opts, httpx.WithKeyValue(
			"algs",
			strings.Join(policy.DPoPAlgorithms, " "),
		))
	}

	header := make(http.Header)
	header.Add("WWW-Authenticate", httpx.NewHeader(opts...))

	return &Challenge{
		StatusCode: http.StatusUnauthorized,
		Headers:    header,
	}, nil
}

type NonceIssuer interface {
	IssueNonce(binding [32]byte) (string, error)
}

type UseDPoPNonceError struct {
	oauth2ChallengeError

	issuer  NonceIssuer
	binding [32]byte
}

func NewUseDPoPNonceError(
	issuer NonceIssuer,
	binding [32]byte,
	message string,
) *UseDPoPNonceError {
	return &UseDPoPNonceError{
		oauth2ChallengeError: oauth2ChallengeError{
			message: message,
			scheme:  SchemeDPoP,
		},
		issuer:  issuer,
		binding: binding,
	}
}

func (e *UseDPoPNonceError) Challenge(
	policy ChallengePolicy,
) (*Challenge, error) {
	nonce, err := e.issuer.IssueNonce(e.binding)
	if err != nil {
		return nil, err
	}

	opts := e.commonParams(policy, "use_dpop_nonce")
	header := make(http.Header)

	header.Add("WWW-Authenticate", httpx.NewHeader(opts...))
	header.Set("DPoP-Nonce", nonce)

	return &Challenge{
		StatusCode: http.StatusUnauthorized,
		Headers:    header,
	}, nil
}
