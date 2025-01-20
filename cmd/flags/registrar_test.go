package flags

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestRegisterGlobalFlags(t *testing.T) {
	t.Parallel()

	// GIVEN
	cmd := &cobra.Command{
		Use: "test",
	}

	// WHEN
	RegisterGlobalFlags(cmd)

	// THEN
	configFlag := cmd.PersistentFlags().Lookup(Config)
	assert.NotNil(t, configFlag)
	assert.Equal(t, "c", configFlag.Shorthand)
	assert.Empty(t, configFlag.DefValue)
	assert.NotEmpty(t, configFlag.Usage)

	envPrefixFlag := cmd.PersistentFlags().Lookup(EnvironmentConfigPrefix)
	assert.NotNil(t, envPrefixFlag)
	assert.Empty(t, envPrefixFlag.Shorthand)
	assert.Equal(t, "HEIMDALLCFG_", envPrefixFlag.DefValue)
	assert.NotEmpty(t, envPrefixFlag.Usage)

	skipAllSecurityEnforcementFlag := cmd.PersistentFlags().Lookup(SkipAllSecurityEnforcement)
	assert.NotNil(t, skipAllSecurityEnforcementFlag)
	assert.Empty(t, skipAllSecurityEnforcementFlag.Shorthand)
	assert.Equal(t, "false", skipAllSecurityEnforcementFlag.DefValue)
	assert.NotEmpty(t, skipAllSecurityEnforcementFlag.Usage)

	skipAllTLSEnforcementFlag := cmd.PersistentFlags().Lookup(SkipAllTLSEnforcement)
	assert.NotNil(t, skipAllTLSEnforcementFlag)
	assert.Empty(t, skipAllTLSEnforcementFlag.Shorthand)
	assert.Equal(t, "false", skipAllTLSEnforcementFlag.DefValue)
	assert.NotEmpty(t, skipAllTLSEnforcementFlag.Usage)

	skipIngressTLSEnforcementFlag := cmd.PersistentFlags().Lookup(SkipIngressTLSEnforcement)
	assert.NotNil(t, skipIngressTLSEnforcementFlag)
	assert.Empty(t, skipIngressTLSEnforcementFlag.Shorthand)
	assert.Equal(t, "false", skipIngressTLSEnforcementFlag.DefValue)
	assert.NotEmpty(t, skipIngressTLSEnforcementFlag.Usage)

	skipEgressTLSEnforcementFlag := cmd.PersistentFlags().Lookup(SkipEgressTLSEnforcement)
	assert.NotNil(t, skipEgressTLSEnforcementFlag)
	assert.Empty(t, skipEgressTLSEnforcementFlag.Shorthand)
	assert.Equal(t, "false", skipEgressTLSEnforcementFlag.DefValue)
	assert.NotEmpty(t, skipEgressTLSEnforcementFlag.Usage)

	skipUpstreamTLSEnforcementFlag := cmd.PersistentFlags().Lookup(SkipUpstreamTLSEnforcement)
	assert.NotNil(t, skipUpstreamTLSEnforcementFlag)
	assert.Empty(t, skipUpstreamTLSEnforcementFlag.Shorthand)
	assert.Equal(t, "false", skipUpstreamTLSEnforcementFlag.DefValue)
	assert.NotEmpty(t, skipUpstreamTLSEnforcementFlag.Usage)

	skipSecureDefaultRuleEnforcementFlag := cmd.PersistentFlags().Lookup(SkipSecureDefaultRuleEnforcement)
	assert.NotNil(t, skipSecureDefaultRuleEnforcementFlag)
	assert.Empty(t, skipSecureDefaultRuleEnforcementFlag.Shorthand)
	assert.Equal(t, "false", skipSecureDefaultRuleEnforcementFlag.DefValue)
	assert.NotEmpty(t, skipSecureDefaultRuleEnforcementFlag.Usage)

	skipSecureTrustedProxiesEnforcementFlag := cmd.PersistentFlags().Lookup(SkipSecureDefaultRuleEnforcement)
	assert.NotNil(t, skipSecureTrustedProxiesEnforcementFlag)
	assert.Empty(t, skipSecureTrustedProxiesEnforcementFlag.Shorthand)
	assert.Equal(t, "false", skipSecureTrustedProxiesEnforcementFlag.DefValue)
	assert.NotEmpty(t, skipSecureTrustedProxiesEnforcementFlag.Usage)
}
