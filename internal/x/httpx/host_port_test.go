package httpx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHostPort(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		value string
		host  string
		port  int
	}{
		{value: "", host: "", port: -1},
		{value: "[:0]:90", host: ":0", port: 90},
		{value: "127.0.0.1:foo", host: "127.0.0.1", port: -1},
	} {
		t.Run(tc.value, func(t *testing.T) {
			// WHEN
			host, port := HostPort(tc.value)

			// THEN
			assert.Equal(t, tc.host, host)
			assert.Equal(t, tc.port, port)
		})
	}
}
