module github.com/dadrus/heimdall

go 1.21

require (
	github.com/Masterminds/sprig/v3 v3.2.3
	github.com/dlclark/regexp2 v1.10.0
	github.com/drone/envsubst/v2 v2.0.0-20210730161058-179042472c46
	github.com/elnormous/contenttype v1.0.4
	github.com/envoyproxy/go-control-plane v0.12.0
	github.com/evanphx/json-patch v5.7.0+incompatible
	github.com/felixge/httpsnoop v1.0.4
	github.com/fsnotify/fsnotify v1.7.0
	github.com/go-co-op/gocron/v2 v2.1.2
	github.com/go-http-utils/etag v0.0.0-20161124023236-513ea8f21eb1
	github.com/go-logr/zerologr v1.2.3
	github.com/go-playground/locales v0.14.1
	github.com/go-playground/universal-translator v0.18.1
	github.com/go-playground/validator/v10 v10.16.0
	github.com/gobwas/glob v0.2.3
	github.com/goccy/go-json v0.10.2
	github.com/google/cel-go v0.18.2
	github.com/google/uuid v1.5.0
	github.com/gorilla/websocket v1.5.1
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.0.1
	github.com/iancoleman/strcase v0.3.0
	github.com/inhies/go-bytesize v0.0.0-20220417184213-4913239db9cf
	github.com/instana/go-otel-exporter v1.0.0
	github.com/jellydator/ttlcache/v3 v3.1.1
	github.com/johannesboyne/gofakes3 v0.0.0-20230914150226-f005f5cc03aa
	github.com/justinas/alice v1.2.0
	github.com/knadh/koanf/maps v0.1.1
	github.com/knadh/koanf/parsers/yaml v0.1.0
	github.com/knadh/koanf/providers/confmap v0.1.0
	github.com/knadh/koanf/providers/env v0.1.0
	github.com/knadh/koanf/providers/rawbytes v0.1.0
	github.com/knadh/koanf/providers/structs v0.1.0
	github.com/knadh/koanf/v2 v2.0.1
	github.com/mitchellh/mapstructure v1.5.0
	github.com/ory/ladon v1.2.0
	github.com/pquerna/cachecontrol v0.2.0
	github.com/prometheus/client_golang v1.18.0
	github.com/rs/cors v1.10.1
	github.com/rs/zerolog v1.31.0
	github.com/santhosh-tekuri/jsonschema/v5 v5.3.1
	github.com/spf13/cobra v1.8.0
	github.com/stretchr/testify v1.8.4
	github.com/tidwall/gjson v1.17.0
	github.com/tonglil/opentelemetry-go-datadog-propagator v0.1.1
	github.com/undefinedlabs/go-mpatch v1.0.7
	github.com/wI2L/jsondiff v0.5.0
	github.com/ybbus/httpretry v1.0.2
	github.com/yl2chen/cidranger v1.0.2
	github.com/youmark/pkcs8 v0.0.0-20201027041543-1326539a0a0a
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.46.1
	go.opentelemetry.io/contrib/instrumentation/host v0.46.1
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.46.1
	go.opentelemetry.io/contrib/instrumentation/runtime v0.46.1
	go.opentelemetry.io/contrib/propagators/autoprop v0.46.1
	go.opentelemetry.io/otel v1.21.0
	go.opentelemetry.io/otel/bridge/opentracing v1.21.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v0.44.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v0.44.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.21.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.21.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.21.0
	go.opentelemetry.io/otel/exporters/prometheus v0.44.0
	go.opentelemetry.io/otel/exporters/zipkin v1.21.0
	go.opentelemetry.io/otel/metric v1.21.0
	go.opentelemetry.io/otel/sdk v1.21.0
	go.opentelemetry.io/otel/sdk/metric v1.21.0
	go.opentelemetry.io/otel/trace v1.21.0
	go.uber.org/fx v1.20.1
	gocloud.dev v0.36.0
	golang.org/x/exp v0.0.0-20240103183307-be819d1f06fc
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240102182953-50ed04b92917
	google.golang.org/grpc v1.60.1
	google.golang.org/protobuf v1.32.0
	gopkg.in/square/go-jose.v2 v2.6.0
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.29.0
	k8s.io/apimachinery v0.29.0
	k8s.io/client-go v0.29.0
	k8s.io/klog/v2 v2.120.0
)

require (
	cloud.google.com/go v0.111.0 // indirect
	cloud.google.com/go/compute v1.23.3 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	cloud.google.com/go/iam v1.1.5 // indirect
	cloud.google.com/go/storage v1.35.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.9.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.4.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.5.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.2.0 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.2.0 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.2.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/aws/aws-sdk-go v1.49.0 // indirect
	github.com/aws/aws-sdk-go-v2 v1.24.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.5.4 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.26.1 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.16.12 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.14.10 // indirect
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.15.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.2.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.5.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.7.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.2.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.10.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.2.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.10.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.16.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.47.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.18.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.21.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.26.5 // indirect
	github.com/aws/smithy-go v1.19.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cncf/xds/go v0.0.0-20230607035331-e9ce68804cb4 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.0.2 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.2 // indirect
	github.com/go-http-utils/fresh v0.0.0-20161124030543-7231e26a4b27 // indirect
	github.com/go-http-utils/headers v0.0.0-20181008091004-fed159eddc2a // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.1.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/s2a-go v0.1.7 // indirect
	github.com/google/wire v0.5.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.2 // indirect
	github.com/googleapis/gax-go/v2 v2.12.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.16.0 // indirect
	github.com/huandu/xstrings v1.3.3 // indirect
	github.com/imdario/mergo v0.3.11 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/jonboulle/clockwork v0.4.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/leodido/go-urn v1.2.4 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/matttproud/golang_protobuf_extensions/v2 v2.0.0 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/openzipkin/zipkin-go v0.4.2 // indirect
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.45.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/ryszard/goskiplist v0.0.0-20150312221310-2dfbae5fcf46 // indirect
	github.com/shabbyrobe/gocovmerge v0.0.0-20190829150210-3e036491d500 // indirect
	github.com/shirou/gopsutil/v3 v3.23.10 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stoewer/go-strcase v1.3.0 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/propagators/aws v1.21.1 // indirect
	go.opentelemetry.io/contrib/propagators/b3 v1.21.1 // indirect
	go.opentelemetry.io/contrib/propagators/jaeger v1.21.1 // indirect
	go.opentelemetry.io/contrib/propagators/ot v1.21.1 // indirect
	go.opentelemetry.io/proto/otlp v1.0.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/dig v1.17.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.26.0 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/oauth2 v0.14.0 // indirect
	golang.org/x/sync v0.5.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/term v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/time v0.4.0 // indirect
	golang.org/x/tools v0.16.0 // indirect
	golang.org/x/xerrors v0.0.0-20231012003039-104605ab7028 // indirect
	google.golang.org/api v0.151.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto v0.0.0-20231212172506-995d672761c0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20231211222908-989df2bf70f3 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/utils v0.0.0-20230726121419-3b25d923346b // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)
