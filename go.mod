module github.com/dadrus/heimdall

go 1.20

require (
	github.com/Masterminds/sprig/v3 v3.2.3
	github.com/dlclark/regexp2 v1.9.0
	github.com/drone/envsubst/v2 v2.0.0-20210730161058-179042472c46
	github.com/elnormous/contenttype v1.0.4
	github.com/envoyproxy/go-control-plane v0.11.0
	github.com/fsnotify/fsnotify v1.6.0
	github.com/go-co-op/gocron v1.23.0
	github.com/go-logr/zerologr v1.2.3
	github.com/gobwas/glob v0.2.3
	github.com/goccy/go-json v0.10.2
	github.com/gofiber/adaptor/v2 v2.2.1
	github.com/gofiber/fiber/v2 v2.44.0
	github.com/google/cel-go v0.14.0
	github.com/google/uuid v1.3.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0
	github.com/iancoleman/strcase v0.2.0
	github.com/instana/go-otel-exporter v1.0.0
	github.com/jellydator/ttlcache/v3 v3.0.1
	github.com/johannesboyne/gofakes3 v0.0.0-20230310080033-c0edf658332b
	github.com/knadh/koanf/maps v0.1.1
	github.com/knadh/koanf/parsers/yaml v0.1.0
	github.com/knadh/koanf/providers/confmap v0.1.0
	github.com/knadh/koanf/providers/env v0.1.0
	github.com/knadh/koanf/providers/rawbytes v0.1.0
	github.com/knadh/koanf/providers/structs v0.1.0
	github.com/knadh/koanf/v2 v2.0.1
	github.com/mitchellh/mapstructure v1.5.0
	github.com/ory/ladon v1.2.0
	github.com/pquerna/cachecontrol v0.1.0
	github.com/prometheus/client_golang v1.15.0
	github.com/prometheus/client_model v0.3.0
	github.com/rs/zerolog v1.29.1
	github.com/santhosh-tekuri/jsonschema/v5 v5.3.0
	github.com/spf13/cobra v1.7.0
	github.com/stretchr/testify v1.8.2
	github.com/tidwall/gjson v1.14.4
	github.com/tonglil/opentelemetry-go-datadog-propagator v0.1.0
	github.com/undefinedlabs/go-mpatch v1.0.6
	github.com/valyala/fasthttp v1.46.0
	github.com/ybbus/httpretry v1.0.2
	github.com/yl2chen/cidranger v1.0.2
	github.com/youmark/pkcs8 v0.0.0-20201027041543-1326539a0a0a
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.40.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.40.0
	go.opentelemetry.io/contrib/propagators/autoprop v0.41.0
	go.opentelemetry.io/otel v1.15.0
	go.opentelemetry.io/otel/bridge/opentracing v1.15.0
	go.opentelemetry.io/otel/exporters/jaeger v1.15.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.15.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.15.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.15.0
	go.opentelemetry.io/otel/exporters/zipkin v1.15.0
	go.opentelemetry.io/otel/sdk v1.15.0
	go.opentelemetry.io/otel/trace v1.15.0
	go.uber.org/fx v1.19.2
	gocloud.dev v0.29.0
	golang.org/x/exp v0.0.0-20230425010034-47ecfdc1ba53
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1
	google.golang.org/grpc v1.54.0
	google.golang.org/protobuf v1.30.0
	gopkg.in/square/go-jose.v2 v2.6.0
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/apimachinery v0.27.1
	k8s.io/client-go v0.27.1
	k8s.io/klog/v2 v2.100.1
)

require (
	cloud.google.com/go v0.110.0 // indirect
	cloud.google.com/go/compute v1.19.0 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	cloud.google.com/go/iam v0.13.0 // indirect
	cloud.google.com/go/storage v1.29.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.3.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.2.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.1.2 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.0.0 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v0.8.1 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.2.0 // indirect
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/antlr/antlr4/runtime/Go/antlr/v4 v4.0.0-20230305170008-8188dc5388df // indirect
	github.com/aws/aws-sdk-go v1.44.200 // indirect
	github.com/aws/aws-sdk-go-v2 v1.17.4 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.4.10 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.18.12 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.13.12 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.22 // indirect
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.11.51 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.22 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.29 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.0.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.1.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.22 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.13.22 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.30.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.14.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.18.3 // indirect
	github.com/aws/smithy-go v1.13.5 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cncf/xds/go v0.0.0-20230105202645-06c439db220b // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/envoyproxy/protoc-gen-validate v0.9.1 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.4.3 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/wire v0.5.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.3 // indirect
	github.com/googleapis/gax-go/v2 v2.7.1 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.11.3 // indirect
	github.com/huandu/xstrings v1.3.3 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.16.3 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.18 // indirect
	github.com/mattn/go-runewidth v0.0.14 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/openzipkin/zipkin-go v0.4.1 // indirect
	github.com/philhofer/fwd v1.1.2 // indirect
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/common v0.42.0 // indirect
	github.com/prometheus/procfs v0.9.0 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/ryszard/goskiplist v0.0.0-20150312221310-2dfbae5fcf46 // indirect
	github.com/savsgio/dictpool v0.0.0-20221023140959-7bf2e61cea94 // indirect
	github.com/savsgio/gotils v0.0.0-20230208104028-c358bd845dee // indirect
	github.com/shabbyrobe/gocovmerge v0.0.0-20180507124511-f6ea450bfb63 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tinylib/msgp v1.1.8 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/tcplisten v1.0.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/propagators/aws v1.16.0 // indirect
	go.opentelemetry.io/contrib/propagators/b3 v1.16.0 // indirect
	go.opentelemetry.io/contrib/propagators/jaeger v1.16.0 // indirect
	go.opentelemetry.io/contrib/propagators/ot v1.16.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/internal/retry v1.15.0 // indirect
	go.opentelemetry.io/otel/metric v0.37.0 // indirect
	go.opentelemetry.io/proto/otlp v0.19.0 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/dig v1.16.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.24.0 // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/oauth2 v0.6.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.7.0 // indirect
	golang.org/x/term v0.6.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.7.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/api v0.114.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/api v0.27.1 // indirect
	k8s.io/utils v0.0.0-20230209194617-a36077c30491 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)
