package resolver

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/rancher-sandbox/runtime-enforcer/internal/bpf"
)

type ContainerData struct {
	CgID CgroupID
	Name string
}

type PodData struct {
	UID          PodID
	Name         string
	Namespace    string
	WorkloadName string
	WorkloadType string
	Labels       Labels
	Containers   map[ContainerID]*ContainerData
}

func convertPodData(data *PodData) *podEntry {
	return &podEntry{
		meta: &PodMeta{
			ID:           data.UID,
			Name:         data.Name,
			Namespace:    data.Namespace,
			WorkloadName: data.WorkloadName,
			WorkloadType: data.WorkloadType,
			Labels:       data.Labels,
		},
		containers: make(map[ContainerID]*ContainerMeta),
	}
}

func (r *Resolver) AddPodContainerFromNri(data *PodData) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// NRI provides just one container of a pod, so it's possible we already have some containers for this pod.
	state, ok := r.podCache[data.UID]
	if !ok {
		// we need to add the pod to the cache from 0
		state = convertPodData(data)
	}

	for containerID, container := range data.Containers {
		if info, exists := state.containers[containerID]; exists {
			// this is possible for example when there is a restart in the NRI plugin and we receive all the data again.
			// cID and containerName should never change but as an extra check we return an error for now.
			if info.CgroupID == container.CgID && info.Name == container.Name {
				// If everything is identical, as expected, we can just continue
				continue
			}
			return fmt.Errorf("containerID %s for pod %s already exists. old (name: %s,cID: %d) new (name: %s,cID: %d)",
				containerID,
				data.Name,
				info.Name,
				info.CgroupID,
				container.Name,
				container.CgID)
		}

		state.containers[containerID] = &ContainerMeta{
			CgroupID: container.CgID,
			Name:     container.Name,
			ID:       containerID,
		}

		// populate the cgroup cache
		r.cgroupIDToPodID[container.CgID] = data.UID

		// update the cgtracker map
		if err := r.cgTrackerUpdateFunc(container.CgID, ""); err != nil {
			r.logger.Error("failed to update cgroup tracker map",
				"pod", data.UID,
				"containerID", containerID,
				"error", err)
			continue
		}
	}

	// we update back the cache
	r.podCache[data.UID] = state

	if err := r.applyPolicyToPodIfPresent(state); err != nil {
		r.logger.Error("failed to apply policy to pod",
			"error", err,
		)
	}
	return nil
}

func (r *Resolver) RemovePodContainerFromNri(podID PodID, containerID ContainerID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, ok := r.podCache[podID]
	if !ok {
		return fmt.Errorf("pod %s not found", podID)
	}

	// remove the container from the pod
	container, ok := state.containers[containerID]
	if !ok {
		// container not found
		return fmt.Errorf("container %s not found for pod %s", containerID, podID)
	}

	if len(state.containers) == 1 {
		// if this was the last container, we need to remove the pod from the cache
		delete(r.podCache, podID)
	} else {
		// otherwise we just delete the container inside the pod
		delete(state.containers, containerID)
	}

	// remove the cgroup ID from the cache
	delete(r.cgroupIDToPodID, container.CgroupID)

	return r.cgroupToPolicyMapUpdateFunc(PolicyIDNone, []CgroupID{container.CgroupID}, bpf.RemoveCgroups)
}

func (r *Resolver) NRISynchronized() {
	r.nriSynchronized.Store(true)
}

func (r *Resolver) Ping(_ *http.Request) error {
	if !r.nriSynchronized.Load() {
		r.logger.Warn("NRI handler has not yet synchronized")
		return errors.New("NRI handler has not yet synchronized")
	}
	return nil
}
