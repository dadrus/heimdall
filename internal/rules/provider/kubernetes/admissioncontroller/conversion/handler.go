package conversion

import (
	"net/http"

	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/admissioncontroller/webhook"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

func NewHandler(factory rule.Factory, authClass string) http.Handler {
	return webhook.New(&rulesetConverter{}, &review{})
}
