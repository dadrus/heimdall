package httpcache

const (
	cacheKeyNamespace = "heimdall-http-cache:v1"

	variantIndexFormatVersion  = 1
	maxVariantIndexSize        = 1 << 20
	maxVariantEntriesPerTarget = 128
)
