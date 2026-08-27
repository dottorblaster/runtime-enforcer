package debugger

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestClusterPodViewHelpers(t *testing.T) {
	podUID := "uid-1"
	podName := "pod-a"
	podNamespace := "default"
	containerID1 := "cid1"
	containerName1 := "c1"

	clusterView := &clusterPodView{
		id:        podUID,
		name:      podName,
		namespace: podNamespace,
		containers: map[containerID]*clusterContainerMeta{
			containerID1: {id: containerID1, name: containerName1},
		},
	}

	require.Equal(t, podUID, clusterView.sortKey())
	require.Equal(t, podName, clusterView.getName())
	require.Equal(t, podNamespace, clusterView.getNamespace())
	require.Len(t, clusterView.getContainers(), 1)
	require.Equal(t, containerID1, clusterView.getContainers()[containerID1].id)
	require.Equal(t, containerName1, clusterView.getContainers()[containerID1].name)
}

func TestExtractContainerID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "containerd prefix is stripped",
			input:    "containerd://d4813c4da49cbaa50542f86bd077608e5d3da101efef52642346803c4d5a902b",
			expected: "d4813c4da49cbaa50542f86bd077608e5d3da101efef52642346803c4d5a902b",
		},
		{
			name:     "docker prefix is stripped",
			input:    "docker://abc123def456",
			expected: "abc123def456",
		},
		{
			name:     "crio prefix is stripped",
			input:    "cri-o://somecontainerid",
			expected: "somecontainerid",
		},
		{
			name:     "no prefix leaves the string unchanged",
			input:    "plaincontainerid",
			expected: "plaincontainerid",
		},
		{
			name:     "empty string returns empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractContainerID(tc.input)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestNewClusterPodView(t *testing.T) {
	tests := []struct {
		name         string
		pod          *corev1.Pod
		expectedView *clusterPodView
	}{
		{
			name: "simple pod",
			pod: &corev1.Pod{
				Name:      "my-pod",
				Namespace: "my-namespace",
				UID:       types.UID("uid-1234"),
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{ContainerID: "containerd://cid1", Name: "main"},
					},
				},
			},
			expectedView: &clusterPodView{
				id:        "uid-1234",
				name:      "my-pod",
				namespace: "my-namespace",
				containers: map[containerID]*clusterContainerMeta{
					"cid1": {
						id:         "cid1",
						name:       "main",
						terminated: false,
					},
				},
			},
		},
		{
			name: "static pod",
			pod: &corev1.Pod{
				Name:      "static-pod",
				Namespace: "kube-system",
				UID:       types.UID("api-server-generated-uid"),
				Annotations: map[string]string{
					staticPodAnnotation: "mirror-uid",
				},
				Status: corev1.PodStatus{
					InitContainerStatuses: []corev1.ContainerStatus{
						{
							ContainerID: "containerd://init1",
							Name:        "init-container",
							State: corev1.ContainerState{
								Terminated: &corev1.ContainerStateTerminated{
									ContainerID: "containerd://init1",
								},
							},
						},
					},
					ContainerStatuses: []corev1.ContainerStatus{
						{
							ContainerID: "containerd://main2",
							Name:        "main-container",
							LastTerminationState: corev1.ContainerState{
								Terminated: &corev1.ContainerStateTerminated{
									ContainerID: "containerd://main1",
								},
							},
						},
					},
					EphemeralContainerStatuses: []corev1.ContainerStatus{
						{ContainerID: "containerd://eph1", Name: "debug-container"},
					},
				},
			},
			expectedView: &clusterPodView{
				id:        "mirror-uid",
				name:      "static-pod",
				namespace: "kube-system",
				containers: map[containerID]*clusterContainerMeta{
					"init1": &clusterContainerMeta{
						id:         "init1",
						name:       "init-container",
						terminated: true,
					},
					"main2": &clusterContainerMeta{
						id:         "main2",
						name:       "main-container",
						terminated: false,
					},
					"main1": &clusterContainerMeta{
						id:         "main1",
						name:       "main-container",
						terminated: true,
					},
					"eph1": &clusterContainerMeta{
						id:         "eph1",
						name:       "debug-container",
						terminated: false,
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			view := newClusterPodView(tc.pod)
			require.Equal(t, tc.expectedView, view)
		})
	}
}

func TestAddContainerToPodView(t *testing.T) {
	tests := []struct {
		name               string
		containerStatus    *corev1.ContainerStatus
		expectedContainers map[containerID]*clusterContainerMeta
	}{
		{
			name: "terminated container",
			containerStatus: &corev1.ContainerStatus{
				ContainerID: "containerd://terminatedID",
				Name:        "terminated-container",
				State: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ContainerID: "containerd://terminatedID",
					},
				},
			},
			expectedContainers: map[containerID]*clusterContainerMeta{
				"terminatedID": {
					id:         "terminatedID",
					name:       "terminated-container",
					terminated: true,
				},
			},
		},
		{
			name: "restarting container",
			containerStatus: &corev1.ContainerStatus{
				ContainerID: "containerd://restartedID",
				Name:        "name1",
				LastTerminationState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ContainerID: "containerd://terminatedID",
					},
				},
			},
			expectedContainers: map[containerID]*clusterContainerMeta{
				"terminatedID": {
					id:         "terminatedID",
					name:       "name1",
					terminated: true,
				},
				"restartedID": {
					id:         "restartedID",
					name:       "name1",
					terminated: false,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			podView := &clusterPodView{
				containers: make(map[containerID]*clusterContainerMeta),
			}
			addContainerToPodView(tc.containerStatus, podView)
			require.Equal(t, tc.expectedContainers, podView.containers)
		})
	}
}
