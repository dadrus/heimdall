package prometheus

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestDefaults(t *testing.T) {
	t.Parallel()

	assert.Equal(t, prometheus.DefaultRegisterer, defaultOptions.registerer)
	assert.Empty(t, defaultOptions.labels)
	assert.Equal(t, "http", defaultOptions.namespace)
	assert.Empty(t, defaultOptions.subsystem)
	assert.NotNil(t, defaultOptions.labels)
	assert.Empty(t, defaultOptions.labels)
	assert.NotNil(t, defaultOptions.filterOperation)
	assert.False(t, defaultOptions.filterOperation(nil))
}
