package serve

import (
	"strconv"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCreateDecisionApp(t *testing.T) {
	// this test verifies that all dependencies are resolved
	// and nothing has been forgotten
	port1, err := testsupport.GetFreePort()
	require.NoError(t, err)

	port2, err := testsupport.GetFreePort()
	require.NoError(t, err)

	t.Setenv("SERVE_DECISION_PORT", strconv.Itoa(port1))
	t.Setenv("SERVE_MANAGEMENT_PORT", strconv.Itoa(port2))

	_, err = createDecisionApp(&cobra.Command{})
	require.NoError(t, err)
}
