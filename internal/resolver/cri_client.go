package resolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"

	"github.com/neuvector/runtime-enforcer/internal/cgroups"
	"github.com/tidwall/gjson"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	criapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

var (
	errNotUnix = errors.New("only unix endpoints are supported")
)

// The resolver should try to open a new client if the previous one failed.
type criResolver struct {
	ctx        context.Context
	client     criapi.RuntimeServiceClient
	logger     *slog.Logger
	endpoint   string
	cgroupRoot string
}

func newCRIResolver(ctx context.Context, logger *slog.Logger) (*criResolver, error) {
	criClient := &criResolver{
		ctx:    ctx,
		logger: logger.With("component", "cri-client"),
	}

	var err error
	// We compute the cgroup root only once here to avoid doing it for every container
	criClient.cgroupRoot, err = cgroups.GetHostCgroupRoot()
	criClient.logger.WarnContext(ctx, "detected cgroup root", "path", criClient.cgroupRoot)
	if err != nil {
		return nil, err
	}

	// We try to create the client here so that we can fail fast if no endpoint is reachable
	if os.Getenv("CUSTOM_CRI_SOCKET_PATH") != "" {
		criClient.endpoint = os.Getenv("CUSTOM_CRI_SOCKET_PATH")
		criClient.endpoint = "unix://" + criClient.endpoint
		criClient.logger.InfoContext(ctx, "using custom CRI socket path", "path", criClient.endpoint)
		criClient.client, err = newClientTry(criClient.endpoint)
		if err != nil {
			return nil, err
		}
		return criClient, nil
	}

	for _, ep := range []string{
		"unix:///run/containerd/containerd.sock",
		"unix:///run/crio/crio.sock",
		"unix:///var/run/cri-dockerd.sock",
	} {
		criClient.endpoint = ep
		criClient.client, err = newClientTry(criClient.endpoint)
		if err == nil {
			criClient.logger.InfoContext(ctx, "created CRI client", "endpoint", criClient.endpoint)
			return criClient, nil
		}
		criClient.logger.InfoContext(ctx, "cannot create CRI client", "endpoint", criClient.endpoint, "error", err)
	}
	return nil, err
}

func newClientTry(endpoint string) (criapi.RuntimeServiceClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "unix" {
		return nil, errNotUnix
	}

	conn, err := grpc.NewClient(endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}

	rtcli := criapi.NewRuntimeServiceClient(conn)
	if _, err = rtcli.Version(context.Background(), &criapi.VersionRequest{}); err != nil {
		return nil, fmt.Errorf("validate CRI v1 runtime API for endpoint %q: %w", endpoint, err)
	}
	return rtcli, nil
}

func (c *criResolver) getCgroupPath(containerID string) (string, error) {
	req := criapi.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}
	// todo!: we need to handle the case in which we need to recreate the client
	res, err := c.client.ContainerStatus(c.ctx, &req)
	if err != nil {
		return "", err
	}

	info := res.GetInfo()
	if info == nil {
		return "", errors.New("no container info")
	}

	var path, containerJSON string
	if infoJSON, ok := info["info"]; ok {
		containerJSON = infoJSON
		// this path doesn't work for cri-dockerd. Minikube by default runs with cri-dockerd.
		path = "runtimeSpec.linux.cgroupsPath"
	} else {
		return "", errors.New("could not find info")
	}

	ret := gjson.Get(containerJSON, path).String()
	if ret == "" {
		return "", errors.New("failed to find cgroupsPath in json")
	}
	return cgroups.ParseCgroupsPath(ret)
}

func (c *criResolver) resolveCgroup(containerID string) (uint64, string, error) {
	// this is extracted from the container runtime
	cgPath, err := c.getCgroupPath(containerID)
	if err != nil {
		return 0, "", err
	}

	path := filepath.Join(c.cgroupRoot, cgPath)
	cgID, err := cgroups.GetCgroupIDFromPath(path)
	if err != nil {
		return 0, "", err
	}
	return cgID, path, nil
}
