package errorhandlers

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ErrorConditionMatcher struct {
	Error  *ErrorTypeMatcher `mapstructure:"error"`
	CIDR   *CIDRMatcher      `mapstructure:"request_cidr"`
	Header *HeaderMatcher    `mapstructure:"request_header"`
}

func (ecm *ErrorConditionMatcher) Validate() error {
	if ecm.Error == nil && ecm.CIDR == nil && ecm.Header == nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "no error conditions configured")
	}

	return nil
}

func (ecm *ErrorConditionMatcher) Match(ctx heimdall.Context, err error) bool {
	if ecm.Error != nil && ecm.Error.Match(err) {
		return true
	}

	if ecm.CIDR != nil && ecm.CIDR.Match(ctx.RequestClientIPs()...) {
		return true
	}

	if ecm.Header != nil && ecm.Header.Match(ctx.RequestHeaders()) {
		return true
	}

	return false
}
