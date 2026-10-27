locals {
  heimdall_chart_path    = abspath("${path.module}/../../../../charts/heimdall")
  heimdall_chart_version = yamldecode(file("${local.heimdall_chart_path}/Chart.yaml")).version
}
