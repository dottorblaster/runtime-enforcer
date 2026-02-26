package resolver

import (
	"errors"
	"fmt"
)

const (
	notFound = "not-found"
)

type KubeInfo struct {
	PodID         string
	PodName       string
	Namespace     string
	ContainerName string
	WorkloadName  string
	WorkloadType  string
	ContainerID   string
	Labels        Labels
}

var (
	// ErrMissingPodUID is returned when no Pod UID could be found for the given cgroup ID.
	ErrMissingPodUID = errors.New("missing pod UID for cgroup ID")

	// ErrMissingPodInfo is returned when the Pod UID was found, but
	// the detailed Pod information is missing.
	ErrMissingPodInfo = errors.New("missing pod info for found pod ID")
)

func (r *Resolver) GetKubeInfo(cgID CgroupID) (*KubeInfo, error) {
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
	for cID, info := range pod.containers {
		if cgID == info.CgroupID {
			containerName = info.Name
			containerID = cID
			break
		}
	}

	return &KubeInfo{
		PodID:         podID,
		PodName:       pod.meta.Name,
		Namespace:     pod.meta.Namespace,
		ContainerName: containerName,
		WorkloadName:  pod.meta.WorkloadName,
		WorkloadType:  pod.meta.WorkloadType,
		ContainerID:   containerID,
		Labels:        pod.meta.Labels,
	}, nil
}
