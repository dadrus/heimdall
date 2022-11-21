package v1alpha1

//go:generate controller-gen object paths=$GOFILE

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/dadrus/heimdall/internal/config"
)

// +kubebuilder:object:generate=true
type RuleSetSpec struct {
	AuthClass string              `json:"authClass"`
	Rules     []config.RuleConfig `json:"rules"`
}

// +kubebuilder:object:generate=true
type RuleSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec RuleSetSpec `json:"spec"`
}

func (in *RuleSet) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// +kubebuilder:object:generate=true
type RuleSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []RuleSet `json:"items"`
}

func (in *RuleSetList) DeepCopyObject() runtime.Object { return in.DeepCopy() }
