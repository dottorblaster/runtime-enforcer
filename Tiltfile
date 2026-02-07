tilt_settings_file = "./tilt-settings.yaml"
settings = read_yaml(tilt_settings_file)

allow_k8s_contexts(settings.get("clusters"))

update_settings(
    k8s_upsert_timeout_secs=180,
)

# while it takes some time to install cert manager, it's okay to wait 
# because we rely on its ca injector to setup our mutating webhook.
load('ext://cert_manager', 'deploy_cert_manager')

deploy_cert_manager(version="v1.18.2")

load("ext://helm_resource", "helm_resource", "helm_repo")
helm_repo("jetstack", "https://charts.jetstack.io")
helm_resource(
    "cert-manager-csi-driver",
    "jetstack/cert-manager-csi-driver",
    namespace="cert-manager",
)

# Create the namespace
# This is required since the helm() function doesn't support the create_namespace flag
load("ext://namespace", "namespace_create")
namespace_create("runtime-enforcer")

operator_image = settings.get("operator").get("image")
agent_image = settings.get("agent").get("image")

helm_options = [
        "operator.manager.image.repository=" + operator_image,
        "agent.agent.image.repository=" + agent_image,
        "operator.replicas=1",
        "operator.manager.containerSecurityContext.runAsUser=null",
        "operator.podSecurityContext.runAsNonRoot=false",
        "agent.agent.containerSecurityContext.runAsUser=null",
        "agent.podSecurityContext.runAsNonRoot=false",
]

yaml = helm(
    "./charts/runtime-enforcer",
    name="runtime-enforcer",
    namespace="runtime-enforcer",
    set=helm_options
)

k8s_yaml(yaml)

# Hot reloading containers
local_resource(
    "operator_tilt",
    "make operator",
    deps=[
        "go.mod",
        "go.sum",
        "cmd/operator",
        "api",
        "internal/controller",
        "proto",
    ],
)

entrypoint = ["/operator"]
dockerfile = "./hack/Dockerfile.operator.tilt"

load("ext://restart_process", "docker_build_with_restart")
docker_build_with_restart(
    operator_image,
    ".",
    dockerfile=dockerfile,
    entrypoint=entrypoint,
    # `only` here is important, otherwise, the container will get updated
    # on _any_ file change.
    only=[
        "./bin/operator",
    ],
    live_update=[
        sync("./bin/operator", "/operator"),
    ],
)

exclusions = [
    "internal/bpf/bpf_**",
    "internal/controller/"
]

local_resource(
    "agent_tilt",
    "make agent",
    deps=[
        "go.mod",
        "go.sum",
        "cmd/agent",
        "api",
        "internal",
        "pkg",
        "bpf",
        "proto",
    ],
    ignore = exclusions,
)

entrypoint = ["/agent"]
# We use a specific Dockerfile since tilt can't run on a scratch container.
dockerfile = "./hack/Dockerfile.agent.tilt"

load("ext://restart_process", "docker_build_with_restart")
docker_build_with_restart(
    agent_image,
    ".",
    dockerfile=dockerfile,
    entrypoint=entrypoint,
    # `only` here is important, otherwise, the container will get updated
    # on _any_ file change.
    only=[
        "./bin/agent",
    ],
    live_update=[
        sync("./bin/agent", "/agent"),
    ],
)
