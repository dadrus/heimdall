package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogFormatToString(t *testing.T) {
	assert.Equal(t, "text", LogTextFormat.String())
	assert.Equal(t, "gelf", LogGelfFormat.String())
}
