package serve

import (
	"strconv"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCreateProxyApp(t *testing.T) {
	// this test verifies that all dependencies are resolved
	// and nothing has been forgotten
	port1, err := testsupport.GetFreePort()
	require.NoError(t, err)

	port2, err := testsupport.GetFreePort()
	require.NoError(t, err)

	t.Setenv("SERVE_PROXY_PORT", strconv.Itoa(port1))
	t.Setenv("SERVE_MANAGEMENT_PORT", strconv.Itoa(port2))

	_, err = createProxyApp(&cobra.Command{})
	require.NoError(t, err)
}
