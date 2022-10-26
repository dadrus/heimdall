module github.com/dadrus/heimdall

go 1.19

require (
	github.com/Masterminds/sprig/v3 v3.2.2
	github.com/ansrivas/fiberprometheus/v2 v2.4.1
	github.com/dlclark/regexp2 v1.7.0
	github.com/dop251/goja v0.0.0-20221019153710-09250e0eba20
	github.com/fsnotify/fsnotify v1.6.0
	github.com/go-co-op/gocron v1.17.1
	github.com/gobwas/glob v0.2.3
	github.com/goccy/go-json v0.9.11
	github.com/gofiber/fiber/v2 v2.38.1
	github.com/google/uuid v1.3.0
	github.com/iancoleman/strcase v0.2.0
	github.com/instana/go-otel-exporter v0.0.0-20220908102301-52c5d8dbfd86
	github.com/jellydator/ttlcache/v3 v3.0.0
	github.com/knadh/koanf v1.4.4
	github.com/mitchellh/mapstructure v1.5.0
	github.com/ory/ladon v1.2.0
	github.com/rs/zerolog v1.28.0
	github.com/santhosh-tekuri/jsonschema/v5 v5.0.1
	github.com/spf13/cobra v1.6.0
	github.com/stretchr/testify v1.8.0
	github.com/tidwall/gjson v1.14.3
	github.com/tonglil/opentelemetry-go-datadog-propagator v0.1.0
	github.com/valyala/fasthttp v1.40.0
	github.com/ybbus/httpretry v1.0.1
	github.com/yl2chen/cidranger v1.0.2
	github.com/youmark/pkcs8 v0.0.0-20201027041543-1326539a0a0a
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.36.4
	go.opentelemetry.io/contrib/propagators/autoprop v0.36.4
	go.opentelemetry.io/otel v1.11.1
	go.opentelemetry.io/otel/bridge/opentracing v1.11.1
	go.opentelemetry.io/otel/exporters/jaeger v1.11.1
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.11.1
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.11.1
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.11.1
	go.opentelemetry.io/otel/exporters/zipkin v1.11.1
	go.opentelemetry.io/otel/sdk v1.11.1
	go.opentelemetry.io/otel/trace v1.11.1
	go.uber.org/fx v1.18.2
	golang.org/x/exp v0.0.0-20221026153819-32f3d567a233
	gopkg.in/square/go-jose.v2 v2.6.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.1.1 // indirect
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.1.3 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-sourcemap/sourcemap v2.1.3+incompatible // indirect
	github.com/gofiber/adaptor/v2 v2.1.25 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.7.0 // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/klauspost/compress v1.15.11 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/openzipkin/zipkin-go v0.4.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.12.2 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.32.1 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.4.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/tcplisten v1.0.0 // indirect
	go.opentelemetry.io/contrib/propagators/aws v1.11.1 // indirect
	go.opentelemetry.io/contrib/propagators/b3 v1.11.1 // indirect
	go.opentelemetry.io/contrib/propagators/jaeger v1.11.1 // indirect
	go.opentelemetry.io/contrib/propagators/ot v1.11.1 // indirect
	go.opentelemetry.io/otel/exporters/otlp/internal/retry v1.11.1 // indirect
	go.opentelemetry.io/otel/metric v0.33.0 // indirect
	go.opentelemetry.io/proto/otlp v0.19.0 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/dig v1.15.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	go.uber.org/zap v1.17.0 // indirect
	golang.org/x/crypto v0.0.0-20221010152910-d6f0a8c073c2 // indirect
	golang.org/x/net v0.0.0-20221004154528-8021a29435af // indirect
	golang.org/x/sync v0.0.0-20220722155255-886fb9371eb4 // indirect
	golang.org/x/sys v0.1.0 // indirect
	golang.org/x/text v0.3.8 // indirect
	google.golang.org/genproto v0.0.0-20221010155953-15ba04fc1c0e // indirect
	google.golang.org/grpc v1.50.1 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
)

replace (
	golang.org/x/net v0.0.0-20220722155237-a158d28d115b => golang.org/x/net v0.0.0-20221004154528-8021a29435af
	golang.org/x/text v0.3.7 => golang.org/x/text v0.3.8
)
