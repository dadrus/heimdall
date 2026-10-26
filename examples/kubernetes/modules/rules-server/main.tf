resource "kubernetes_namespace_v1" "rules_server" {
  metadata {
    name = var.namespace
  }
}

resource "kubernetes_config_map_v1" "nginx" {
  metadata {
    name      = "rules-server-nginx"
    namespace = kubernetes_namespace_v1.rules_server.metadata[0].name
  }

  data = {
    "nginx.conf" = file("${path.module}/nginx.conf")
  }
}

resource "kubectl_manifest" "certificate" {
  yaml_body = templatefile("${path.module}/manifests/certificate.yaml", {
    namespace      = kubernetes_namespace_v1.rules_server.metadata[0].name
    cluster_domain = var.cluster_domain
  })
}

resource "kubectl_manifest" "deployment" {
  depends_on = [kubectl_manifest.certificate, kubernetes_config_map_v1.nginx]

  yaml_body = templatefile("${path.module}/manifests/deployment.yaml", {
    namespace             = kubernetes_namespace_v1.rules_server.metadata[0].name
    image                 = var.image
    nginx_configmap_name  = kubernetes_config_map_v1.nginx.metadata[0].name
    rules_configmap_name  = "echo-app-rules"
    nginx_config_checksum = sha256(file("${path.module}/nginx.conf"))
  })

  wait_for_rollout = true
}

resource "kubectl_manifest" "service" {
  yaml_body = templatefile("${path.module}/manifests/service.yaml", {
    namespace = kubernetes_namespace_v1.rules_server.metadata[0].name
  })
}
