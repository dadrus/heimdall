package requestcontext

import (
	"iter"
	"net/http"
	"strings"
)

func ConnectionOptions(headers http.Header) iter.Seq[string] {
	return func(yield func(string) bool) {
		for _, value := range headers.Values("Connection") {
			for option := range strings.SplitSeq(value, ",") {
				name := http.CanonicalHeaderKey(strings.TrimSpace(option))
				if len(name) == 0 {
					continue
				}

				if !yield(name) {
					return
				}
			}
		}
	}
}
