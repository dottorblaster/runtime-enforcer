package resolver

import (
	"fmt"
)

func (r *Resolver) GetContainerView(cgID CgroupID) (*ContainerView, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	podID, ok := r.cgroupIDToPodID[cgID]
	if !ok {
		return nil, fmt.Errorf("no pod UID associated with cgroup ID: %d", cgID)
	}

	pod, ok := r.podCache[podID]
	if !ok {
		return nil, fmt.Errorf("no pod entry associated with pod ID: %s (cgroup ID %d)", podID, cgID)
	}

	for containerID, meta := range pod.containers {
		// we should find a container matching the cgroup ID, otherwise we have an error.
		if cgID == meta.CgroupID {
			return &ContainerView{
				PodMeta: *pod.meta,
				Meta: ContainerMeta{
					ID:       containerID,
					Name:     meta.Name,
					CgroupID: cgID,
				},
			}, nil
		}
	}

	return nil, fmt.Errorf("no container associated with cgroup ID: %d in pod ID: %s", cgID, podID)
}

func (r *Resolver) PodCacheSnapshot() map[PodID]PodView {
	r.mu.Lock()
	defer r.mu.Unlock()

	snapshot := make(map[PodID]PodView, len(r.podCache))
	for podID, entry := range r.podCache {
		snapshot[podID] = entry.toView()
	}
	return snapshot
}
