package v1beta1

import "github.com/dadrus/heimdall/internal/config"

type Step struct {
	ID                string                 `json:"id,omitempty"             yaml:"id,omitempty"`
	Condition         *string                `json:"if,omitempty"             yaml:"if,omitempty"`
	AuthenticatorRef  string                 `json:"authenticator,omitempty"  yaml:"authenticator,omitempty"`
	AuthorizerRef     string                 `json:"authorizer,omitempty"     yaml:"authorizer,omitempty"`
	ContextualizerRef string                 `json:"contextualizer,omitempty" yaml:"contextualizer,omitempty"`
	FinalizerRef      string                 `json:"finalizer,omitempty"      yaml:"finalizer,omitempty"`
	ErrorHandlerRef   string                 `json:"error_handler,omitempty"  yaml:"error_handler,omitempty"`
	Principal         *string                `json:"principal,omitempty"      yaml:"principal,omitempty"`
	Config            config.MechanismConfig `json:"config,omitempty"         yaml:"config,omitempty"`
}

type MechanismReference struct {
	Type string
	Name string
}

func (s *Step) MechanismReference() MechanismReference {
	switch {
	case len(s.AuthenticatorRef) != 0:
		return MechanismReference{Type: "authenticator", Name: s.AuthenticatorRef}
	case len(s.AuthorizerRef) != 0:
		return MechanismReference{Type: "authorizer", Name: s.AuthorizerRef}
	case len(s.ContextualizerRef) != 0:
		return MechanismReference{Type: "contextualizer", Name: s.ContextualizerRef}
	case len(s.FinalizerRef) != 0:
		return MechanismReference{Type: "finalizer", Name: s.FinalizerRef}
	case len(s.ErrorHandlerRef) != 0:
		return MechanismReference{Type: "error_handler", Name: s.ErrorHandlerRef}
	default:
		return MechanismReference{Type: "unknown", Name: ""}
	}
}

func (s *Step) DeepCopyInto(out *Step) {
	*out = *s

	if s.Condition != nil {
		in, out := &s.Condition, &out.Condition
		*out = new(string)
		**out = **in
	}

	if s.Principal != nil {
		in, out := &s.Principal, &out.Principal
		*out = new(string)
		**out = **in
	}

	s.Config.DeepCopyInto(&out.Config)
}
