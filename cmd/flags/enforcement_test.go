package flags

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnforcementSettings(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc                          string
		args                        []string
		enforceSecureDefaultRule    bool
		enforceSecureTrustedProxies bool
		enforceManagementTLS        bool
		enforceIngressTLS           bool
		enforceEgressTLS            bool
		enforceUpstreamTLS          bool
	}{
		{
			uc:   "should skip security settings entirely",
			args: []string{"--" + SkipAllSecurityEnforcement},
		},
		{
			uc:                          "should skip TLS enforcement only",
			args:                        []string{"--" + SkipAllTLSEnforcement},
			enforceSecureDefaultRule:    true,
			enforceSecureTrustedProxies: true,
		},
		{
			uc:                          "should not enforce secure default rule",
			args:                        []string{"--" + SkipSecureDefaultRuleEnforcement},
			enforceManagementTLS:        true,
			enforceIngressTLS:           true,
			enforceEgressTLS:            true,
			enforceUpstreamTLS:          true,
			enforceSecureTrustedProxies: true,
		},
		{
			uc:                       "should not enforce secure trusted proxies",
			args:                     []string{"--" + SkipSecureTrustedProxiesEnforcement},
			enforceSecureDefaultRule: true,
			enforceManagementTLS:     true,
			enforceIngressTLS:        true,
			enforceEgressTLS:         true,
			enforceUpstreamTLS:       true,
		},
		{
			uc:                          "should not enforce ingress TLS",
			args:                        []string{"--" + SkipIngressTLSEnforcement},
			enforceSecureDefaultRule:    true,
			enforceSecureTrustedProxies: true,
			enforceManagementTLS:        true,
			enforceEgressTLS:            true,
			enforceUpstreamTLS:          true,
		},
		{
			uc:                          "should not enforce egress TLS",
			args:                        []string{"--" + SkipEgressTLSEnforcement},
			enforceSecureDefaultRule:    true,
			enforceSecureTrustedProxies: true,
			enforceManagementTLS:        true,
			enforceIngressTLS:           true,
			enforceUpstreamTLS:          true,
		},
		{
			uc:                          "should not enforce upstream TLS",
			args:                        []string{"--" + SkipUpstreamTLSEnforcement},
			enforceSecureDefaultRule:    true,
			enforceSecureTrustedProxies: true,
			enforceManagementTLS:        true,
			enforceIngressTLS:           true,
			enforceEgressTLS:            true,
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			cmd := &cobra.Command{Use: "test"}
			cmd.PersistentFlags().Bool(SkipAllSecurityEnforcement, false, "")
			cmd.PersistentFlags().Bool(SkipAllTLSEnforcement, false, "")
			cmd.PersistentFlags().Bool(SkipIngressTLSEnforcement, false, "")
			cmd.PersistentFlags().Bool(SkipEgressTLSEnforcement, false, "")
			cmd.PersistentFlags().Bool(SkipUpstreamTLSEnforcement, false, "")
			cmd.PersistentFlags().Bool(SkipSecureDefaultRuleEnforcement, false, "")
			cmd.PersistentFlags().Bool(SkipSecureTrustedProxiesEnforcement, false, "")

			cmd.SetArgs(tc.args)

			res, err := cmd.ExecuteC()
			require.NoError(t, err)

			es := EnforcementSettings(res)
			assert.Equal(t, tc.enforceSecureDefaultRule, es.EnforceSecureDefaultRule)
			assert.Equal(t, tc.enforceSecureTrustedProxies, es.EnforceSecureTrustedProxies)
			assert.Equal(t, tc.enforceIngressTLS, es.EnforceIngressTLS)
			assert.Equal(t, tc.enforceEgressTLS, es.EnforceEgressTLS)
			assert.Equal(t, tc.enforceUpstreamTLS, es.EnforceUpstreamTLS)
		})
	}
}
