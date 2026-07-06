package kubectlplugin

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	fakeclient "github.com/rancher-sandbox/runtime-enforcer/pkg/generated/clientset/versioned/fake"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestRunProposalPromote(t *testing.T) {
	t.Parallel()

	const (
		ns   = "test"
		name = "test-deployment"
	)

	tests := []struct {
		name         string
		dryRun       bool
		proposal     *securityv1alpha1.WorkloadPolicyProposal
		policy       *securityv1alpha1.WorkloadPolicy
		expectOutput string
	}{
		{
			name: "promotes proposal and waits for policy",
			proposal: &securityv1alpha1.WorkloadPolicyProposal{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: ns,
				},
			},
			policy: &securityv1alpha1.WorkloadPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: ns,
				},
			},
			expectOutput: fmt.Sprintf(
				"Promoted WorkloadPolicyProposal %q in namespace %q to WorkloadPolicy.",
				name,
				ns,
			),
		},
		{
			name:   "dry-run when not yet promoted",
			dryRun: true,
			proposal: &securityv1alpha1.WorkloadPolicyProposal{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: ns,
				},
			},
			// In dry-run mode, we don't wait for the policy to be created
			policy: nil,
			expectOutput: fmt.Sprintf(
				"WorkloadPolicyProposal %q in namespace %q can be correctly promoted to WorkloadPolicy.",
				name,
				ns,
			),
		},
		{
			name:   "dry-run when already promoted",
			dryRun: true,
			proposal: &securityv1alpha1.WorkloadPolicyProposal{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: ns,
					Labels: map[string]string{
						securityv1alpha1.ProposalPromoteLabelKey: "true",
					},
				},
			},
			expectOutput: fmt.Sprintf(
				"WorkloadPolicyProposal %q in namespace %q is already promoted to WorkloadPolicy.",
				name,
				ns,
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			securityClient := newProposalPromoteTestClient(tt.proposal, tt.policy).SecurityV1alpha1()

			var out bytes.Buffer
			opts := &proposalPromoteOptions{
				commonOptions: commonOptions{
					Namespace: ns,
					DryRun:    tt.dryRun,
				},
				ProposalName: name,
			}
			ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
			defer cancel()

			err := runProposalPromote(ctx, securityClient, opts, &out)
			require.NoError(t, err)

			wpProposal, err := securityClient.WorkloadPolicyProposals(ns).Get(ctx, name, metav1.GetOptions{})
			require.NoError(t, err)

			// The fake client ignores DryRun and still mutates the object, so we
			// still assert the updated label even in dry-run mode.
			require.True(t, wpProposal.HasPromotionLabel())
			require.Contains(t, out.String(), tt.expectOutput)
		})
	}
}

func newProposalPromoteTestClient(
	proposal *securityv1alpha1.WorkloadPolicyProposal,
	policy *securityv1alpha1.WorkloadPolicy,
) *fakeclient.Clientset {
	objects := []runtime.Object{proposal}
	if policy != nil {
		objects = append(objects, policy)
	}

	return fakeclient.NewClientset(objects...)
}

func TestCompleteProposalPromoteArgs(t *testing.T) {
	t.Parallel()
	proposalName := "test-proposal"
	testWorkloadPolicyProposal := &securityv1alpha1.WorkloadPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name: proposalName,
		},
	}

	tf, streams := setupTestFactory(t, testWorkloadPolicyProposal.DeepCopy())
	defer tf.Cleanup()

	cmd := newProposalPromoteCmd(commonCmdDeps{f: tf, ioStreams: streams})
	completes, directive := cmd.ValidArgsFunction(cmd, []string{}, "")
	assert.Equal(t, []string{proposalName}, completes)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
}
