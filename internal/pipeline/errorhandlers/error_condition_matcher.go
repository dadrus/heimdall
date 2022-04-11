package errorhandlers

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ErrorConditionMatcher struct {
	Error   *ErrorTypeMatcher `mapstructure:"error"`
	Request struct {
		CIDR   *CIDRMatcher   `mapstructure:"cidr"`
		Header *HeaderMatcher `mapstructure:"header"`
	} `mapstructure:"request"`
}

func (ecm *ErrorConditionMatcher) Validate() error {
	if ecm.Error == nil && ecm.Request.CIDR == nil && ecm.Request.Header == nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "no error conditions configured")
	}

	return nil
}

func (ecm *ErrorConditionMatcher) Match(ctx heimdall.Context, err error) bool {
	if ecm.Error != nil && !ecm.Error.Match(err) {
		return false
	}

	if ecm.Request.CIDR != nil && !ecm.Request.CIDR.Match(ctx) {
		return false
	}

	if ecm.Request.Header != nil && !ecm.Request.Header.Match(ctx) {
		return false
	}

	return true
}
