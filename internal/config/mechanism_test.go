package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMechanismConfigDeepCopyInto(t *testing.T) {
	t.Parallel()

	// GIVEN
	var out MechanismConfig

	in := MechanismConfig{"foo": "bar", "baz": "zab"}

	// WHEN
	in.DeepCopyInto(&out)

	// THEN
	require.Equal(t, in, out)
}
