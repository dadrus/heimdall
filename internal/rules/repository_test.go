package rules

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddingAndRemovingRules(t *testing.T) {
	t.Parallel()

	r, err := NewRepository(nil, nil, *zerolog.Ctx(context.Background()))
	require.NoError(t, err)

	repo, ok := r.(*repository)
	require.True(t, ok)

	repo.addRule(&rule{id: "1", srcID: "bar"})
	repo.addRule(&rule{id: "2", srcID: "bar"})
	repo.addRule(&rule{id: "3", srcID: "bar"})
	repo.addRule(&rule{id: "4", srcID: "bar"})

	assert.Len(t, repo.rules, 4)

	repo.removeRules("bar")

	assert.Len(t, repo.rules, 0)
}
