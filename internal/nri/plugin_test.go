package nri

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"github.com/rancher-sandbox/runtime-enforcer/internal/resolver"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/workloadkind"
	"github.com/stretchr/testify/require"
)

func newTestPlugin(
	t *testing.T,
	failOpen bool,
	resolveCgroupFunc func(*api.Container) (resolver.CgroupID, error),
) *plugin {
	t.Helper()

	return &plugin{
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		resolver:        resolver.NewTestResolver(t),
		failOpen:        failOpen,
		resolveCgroupID: resolveCgroupFunc,
	}
}

func testPodSandbox() *api.PodSandbox {
	return &api.PodSandbox{
		Id:          "sandbox-id",
		Uid:         "pod-uid",
		Name:        "demo-pod",
		Namespace:   "demo-ns",
		Labels:      map[string]string{"app": "demo"},
		Annotations: map[string]string{},
	}
}

func testContainer() *api.Container {
	return &api.Container{
		Id:   "container-id",
		Name: "app",
		Linux: &api.LinuxContainer{
			CgroupsPath: "/unused/by/mock",
		},
	}
}

func TestPluginStartContainer(t *testing.T) {
	t.Run("adds container to resolver on success", func(t *testing.T) {
		pod := testPodSandbox()
		container := testContainer()

		p := newTestPlugin(t, false, func(*api.Container) (resolver.CgroupID, error) {
			return 100, nil
		})

		err := p.StartContainer(t.Context(), pod, container)
		require.NoError(t, err)

		containerView, err := p.resolver.GetContainerView(100)
		require.NoError(t, err)
		require.Equal(t, &resolver.ContainerView{
			PodMeta: resolver.PodMeta{
				ID:           pod.GetUid(),
				Name:         pod.GetName(),
				Namespace:    pod.GetNamespace(),
				WorkloadName: pod.GetName(),
				WorkloadType: string(workloadkind.Pod),
				Labels:       pod.GetLabels(),
			},
			Meta: resolver.ContainerMeta{
				ID:       container.GetId(),
				Name:     container.GetName(),
				CgroupID: 100,
			},
		}, containerView)
	})

	t.Run("returns nil in fail-open mode when cgroup lookup fails", func(t *testing.T) {
		p := newTestPlugin(t, true, func(*api.Container) (resolver.CgroupID, error) {
			return 0, errors.New("lookup failed")
		})
		pod := testPodSandbox()
		container := testContainer()

		err := p.StartContainer(t.Context(), pod, container)
		require.NoError(t, err)
		require.Empty(t, p.resolver.PodCacheSnapshot())
	})

	t.Run("returns wrapped error in fail-closed mode when cgroup lookup fails", func(t *testing.T) {
		p := newTestPlugin(t, false, func(*api.Container) (resolver.CgroupID, error) {
			return 0, errors.New("lookup failed")
		})

		pod := testPodSandbox()
		container := testContainer()

		err := p.StartContainer(t.Context(), pod, container)
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to get cgroup ID from container: lookup failed")
		require.ErrorContains(t, err, "Runtime-enforcer has prevented the container 'demo-pod/app' from starting")
		require.Empty(t, p.resolver.PodCacheSnapshot())
	})
}
