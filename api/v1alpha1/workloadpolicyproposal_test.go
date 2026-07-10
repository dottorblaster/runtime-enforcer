package v1alpha1

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWorkloadPolicyProposalNamespacedName(t *testing.T) {
	t.Run("nil proposal returns empty string", func(t *testing.T) {
		var p *WorkloadPolicyProposal
		require.Empty(t, p.NamespacedName())
	})

	t.Run("returns namespace/name", func(t *testing.T) {
		p := &WorkloadPolicyProposal{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test-namespace",
				Name:      "test-name",
			},
		}
		require.Equal(t, "test-namespace/test-name", p.NamespacedName())
	})
}

func TestWorkloadPolicyProposalIsFull(t *testing.T) {
	tests := []struct {
		name           string
		executables    int
		expectedIsFull bool
	}{
		{
			name:           "empty proposal is not full",
			executables:    0,
			expectedIsFull: false,
		},
		{
			name:           "proposal below max is not full",
			executables:    policyProposalMaxExecutables - 1,
			expectedIsFull: false,
		},
		{
			name:           "proposal at max is full",
			executables:    policyProposalMaxExecutables,
			expectedIsFull: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &WorkloadPolicyProposal{}
			for i := range tc.executables {
				p.AddProcess("container", "/bin/exe"+strconv.Itoa(i))
			}
			require.Equal(t, tc.expectedIsFull, p.IsFull())
		})
	}
}

func TestWorkloadPolicyProposalAddProcess(t *testing.T) {
	type addProcessCall struct {
		containerName string
		executable    string
	}

	tests := []struct {
		name                        string
		calls                       []addProcessCall
		expectedContainers          int
		expectedAllowedPerContainer map[string][]string
	}{
		{
			name:               "adds executable to new container",
			calls:              []addProcessCall{{"container1", "/bin/sh"}},
			expectedContainers: 1,
			expectedAllowedPerContainer: map[string][]string{
				"container1": {"/bin/sh"},
			},
		},
		{
			name: "adds executable to existing container",
			calls: []addProcessCall{
				{"container1", "/bin/sh"},
				{"container1", "/bin/bash"},
			},
			expectedContainers: 1,
			expectedAllowedPerContainer: map[string][]string{
				"container1": {"/bin/sh", "/bin/bash"},
			},
		},
		{
			name: "does not add duplicate executable",
			calls: []addProcessCall{
				{"container1", "/bin/sh"},
				{"container1", "/bin/sh"},
			},
			expectedContainers: 1,
			expectedAllowedPerContainer: map[string][]string{
				"container1": {"/bin/sh"},
			},
		},
		{
			name: "handles multiple containers independently",
			calls: []addProcessCall{
				{"container1", "/bin/sh"},
				{"container2", "/bin/bash"},
			},
			expectedContainers: 2,
			expectedAllowedPerContainer: map[string][]string{
				"container1": {"/bin/sh"},
				"container2": {"/bin/bash"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &WorkloadPolicyProposal{}
			for _, call := range tc.calls {
				p.AddProcess(call.containerName, call.executable)
			}
			require.Len(t, p.Spec.RulesByContainer, tc.expectedContainers)
			for container, executables := range tc.expectedAllowedPerContainer {
				require.ElementsMatch(t, executables, p.Spec.RulesByContainer[container].Executables.Allowed)
			}
		})
	}
}
