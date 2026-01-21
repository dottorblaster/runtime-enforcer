package nri

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/containerd/nri/pkg/api"
	"github.com/neuvector/runtime-enforcer/internal/cgroups"
	"github.com/neuvector/runtime-enforcer/internal/resolver"
)

func cgroupFromContainer(container *api.Container) (resolver.CgroupID, error) {
	if container == nil {
		// safety check, this should never happen
		return 0, errors.New("received empty container")
	}

	if container.GetLinux() == nil {
		return 0, fmt.Errorf("received container '%s(%s)' without Linux info",
			container.GetName(),
			container.GetId(),
		)
	}

	// Parse the cgroup path
	parsedPath, err := cgroups.ParseCgroupsPath(container.GetLinux().GetCgroupsPath())
	if err != nil {
		return 0, fmt.Errorf("failed to parse cgroup path '%s' for container '%s(%s)': %w",
			container.GetLinux().GetCgroupsPath(),
			container.GetName(),
			container.GetId(),
			err,
		)
	}

	cgRoot, _ := cgroups.GetHostCgroupRoot()
	path := filepath.Join(cgRoot, parsedPath)

	// Get the cgroup ID
	cgroupID, err := cgroups.GetCgroupIDFromPath(path)
	if err != nil {
		return 0, fmt.Errorf("failed to get cgroup ID from path '%s' for container '%s(%s)': %w",
			path,
			container.GetName(),
			container.GetId(),
			err,
		)
	}
	return cgroupID, nil
}
