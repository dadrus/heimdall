package serve

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestRunDecisionModeForEnvoyGRPCRequests(t *testing.T) {
	// this test verifies that all dependencies are resolved
	// and nothing has been forgotten
	port1, err := testsupport.GetFreePort()
	require.NoError(t, err)

	port2, err := testsupport.GetFreePort()
	require.NoError(t, err)

	t.Setenv("HEIMDALLCFG_SERVE_PORT", strconv.Itoa(port1))
	t.Setenv("HEIMDALLCFG_MANAGEMENT_PORT", strconv.Itoa(port2))

	cmd := NewDecisionCommand()
	cmd.SilenceUsage = true
	flags.RegisterGlobalFlags(cmd)

	err = cmd.ParseFlags([]string{"--" + flags.SkipAllSecurityEnforcement, "--" + serveDecisionFlagEnvoyGRPC})
	require.NoError(t, err)

	go func() {
		err = cmd.Execute()
		assert.NoError(t, err)
	}()

	time.Sleep(1000 * time.Millisecond)
}

func TestRunDecisionModeForHTTPRequests(t *testing.T) {
	// this test verifies that all dependencies are resolved
	// and nothing has been forgotten
	port1, err := testsupport.GetFreePort()
	require.NoError(t, err)

	port2, err := testsupport.GetFreePort()
	require.NoError(t, err)

	t.Setenv("HEIMDALLCFG_SERVE_PORT", strconv.Itoa(port1))
	t.Setenv("HEIMDALLCFG_MANAGEMENT_PORT", strconv.Itoa(port2))

	cmd := NewDecisionCommand()
	cmd.SilenceUsage = true
	flags.RegisterGlobalFlags(cmd)

	err = cmd.ParseFlags([]string{"--" + flags.SkipAllSecurityEnforcement})
	require.NoError(t, err)

	go func() {
		err = cmd.Execute()
		assert.NoError(t, err)
	}()

	time.Sleep(500 * time.Millisecond)
}

func TestRunDecisionModeFails(t *testing.T) {
	// this test verifies that all dependencies are resolved
	// and nothing has been forgotten
	port1, err := testsupport.GetFreePort()
	require.NoError(t, err)

	port2, err := testsupport.GetFreePort()
	require.NoError(t, err)

	t.Setenv("HEIMDALLCFG_SERVE_PORT", strconv.Itoa(port1))
	t.Setenv("HEIMDALLCFG_MANAGEMENT_PORT", strconv.Itoa(port2))

	cmd := NewDecisionCommand()
	cmd.SilenceUsage = true
	flags.RegisterGlobalFlags(cmd)

	err = cmd.Execute()
	require.Error(t, err)
	require.ErrorIs(t, err, heimdall.ErrConfiguration)
	// secure config is enforcement, but not done
	require.Contains(t, err.Error(), "configuration is invalid")
}
