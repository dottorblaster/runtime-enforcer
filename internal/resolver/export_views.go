package resolver

import (
	"errors"
	"fmt"
)

const (
	notFound = "not-found"
)

var (
	// ErrMissingPodUID is returned when no Pod UID could be found for the given cgroup ID.
	ErrMissingPodUID = errors.New("missing pod UID for cgroup ID")

	// ErrMissingPodInfo is returned when the Pod UID was found, but
	// the detailed Pod information is missing.
	ErrMissingPodInfo = errors.New("missing pod info for found pod ID")
)

func (r *Resolver) GetContainerView(cgID CgroupID) (*ContainerView, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	podID, ok := r.cgroupIDToPodID[cgID]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrMissingPodUID, cgID)
	}

	pod, ok := r.podCache[podID]
	if !ok {
		return nil, fmt.Errorf("%w: %s (cgroup ID %d)", ErrMissingPodInfo, podID, cgID)
	}

	containerName := notFound
	containerID := notFound
	// even if we have the pod in the cache we need to check
	// we have the container associated with the cgroupID.
	for cID, info := range pod.containers {
		if cgID == info.CgroupID {
			containerName = info.Name
			containerID = cID
			break
		}
	}

	return &ContainerView{
		PodMeta: *pod.meta,
		Meta: ContainerMeta{
			ID:       containerID,
			Name:     containerName,
			CgroupID: cgID,
		},
	}, nil
}
