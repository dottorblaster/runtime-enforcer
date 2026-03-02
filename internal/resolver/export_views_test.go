//nolint:testpackage // testing internal methods
package resolver

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func generateMockPodEntry(n int) (PodID, *podEntry) {
	podID := fmt.Sprintf("pod%d", n)
	return podID, &podEntry{
		meta: &PodMeta{
			ID:           podID,
			Name:         fmt.Sprintf("pod%d", n),
			Namespace:    "default",
			WorkloadName: fmt.Sprintf("workload%d", n),
			WorkloadType: "deployment",
			Labels: map[string]string{
				"app": "my-app",
				"env": "production",
			},
		},
		containers: map[ContainerID]*ContainerMeta{
			strconv.Itoa(n): {
				ID:       strconv.Itoa(n),
				Name:     fmt.Sprintf("container%d", n),
				CgroupID: CgroupID(n),
			},
		},
	}
}

func TestPodCacheSnapshot(t *testing.T) {
	r := newTestResolver(t)

	// Populate the pod cache
	podID1, pod1 := generateMockPodEntry(1)
	podID2, pod2 := generateMockPodEntry(2)
	r.podCache[podID1] = pod1
	r.podCache[podID2] = pod2

	// Now get a first snapshot
	snapshot := r.PodCacheSnapshot()
	expectedSnapshot := map[PodID]PodView{
		podID1: pod1.toView(),
		podID2: pod2.toView(),
	}
	require.Equal(t, expectedSnapshot, snapshot)
	// change the cache values
	r.podCache[podID1].meta.Labels["env"] = "updated-env"
	r.podCache[podID2].containers[ContainerID("2")].Name = "updated-container2"
	// The snapshot should remain the same, all values are copied no references to the initial cache.
	require.NotEqual(t, "updated-env", snapshot[podID1].Meta.Labels["env"])
	require.NotEqual(t, "updated-container2", snapshot[podID2].Containers[ContainerID("2")].Name)
}
