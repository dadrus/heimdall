package serve

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal/config"
)

func TestCreateApp(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{}
	flags.RegisterGlobalFlags(cmd)

	err := cmd.ParseFlags([]string{"--" + flags.SkipAllSecurityEnforcement})
	require.NoError(t, err)

	app, err := createApp(cmd, fx.Supply(config.DecisionMode))
	require.NoError(t, err)
	require.NotNil(t, app)
}
