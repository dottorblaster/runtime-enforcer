package main

import (
	"bytes"
	"context"
	"testing"

	apiv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	fakeclient "github.com/rancher-sandbox/runtime-enforcer/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRunProposalPromoteUpdatesLabelAndWaitsForPolicy(t *testing.T) {
	t.Parallel()

	ns := "test"
	name := "test-deployment"

	proposal := &apiv1alpha1.WorkloadPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
	}

	policy := &apiv1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
	}

	clientset := fakeclient.NewClientset(proposal, policy)
	securityClient := clientset.SecurityV1alpha1()

	var out bytes.Buffer
	opts := &proposalPromoteOptions{
		commonOptions: commonOptions{
			Namespace: ns,
			DryRun:    false,
		},
		ProposalName: name,
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()

	err := runProposalPromote(ctx, securityClient, opts, &out)
	require.NoError(t, err)

	wpProposal, err := securityClient.WorkloadPolicyProposals(ns).Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)

	labels := wpProposal.GetLabels()
	require.NotNil(t, labels, "labels should be set after promotion")
	require.Equal(t, "true", labels[apiv1alpha1.ApprovalLabelKey])
}

func TestRunProposalPromoteDryRun(t *testing.T) {
	t.Parallel()

	ns := "test"
	name := "test-deployment"

	t.Run("dry-run when not yet promoted", func(t *testing.T) {
		t.Parallel()

		proposal := &apiv1alpha1.WorkloadPolicyProposal{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
			},
		}

		// In dry-run mode, the real API server would not persist the change,
		// but the fake client ignores DryRun and still mutates the object.
		// We also pre-create the WorkloadPolicy so that waitForWorkloadPolicy
		// can succeed without timing out.
		policy := &apiv1alpha1.WorkloadPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
			},
		}

		clientset := fakeclient.NewClientset(proposal, policy)
		securityClient := clientset.SecurityV1alpha1()

		var out bytes.Buffer
		opts := &proposalPromoteOptions{
			commonOptions: commonOptions{
				Namespace: ns,
				DryRun:    true,
			},
			ProposalName: name,
		}

		ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
		defer cancel()

		err := runProposalPromote(ctx, securityClient, opts, &out)
		require.NoError(t, err)

		wpProposal, err := securityClient.WorkloadPolicyProposals(ns).Get(ctx, name, metav1.GetOptions{})
		require.NoError(t, err)
		labels := wpProposal.GetLabels()
		require.NotNil(t, labels, "labels should be set on dry-run when using the fake client")
		require.Equal(t, "true", labels[apiv1alpha1.ApprovalLabelKey])

		output := out.String()
		require.Contains(
			t,
			output,
			"Would promote WorkloadPolicyProposal \"test-deployment\" in namespace \"test\" to WorkloadPolicy",
		)
	})

	t.Run("dry-run when already promoted", func(t *testing.T) {
		t.Parallel()

		proposal := &apiv1alpha1.WorkloadPolicyProposal{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
				Labels: map[string]string{
					apiv1alpha1.ApprovalLabelKey: "true",
				},
			},
		}

		clientset := fakeclient.NewClientset(proposal)
		securityClient := clientset.SecurityV1alpha1()

		var out bytes.Buffer
		opts := &proposalPromoteOptions{
			commonOptions: commonOptions{
				Namespace: ns,
				DryRun:    true,
			},
			ProposalName: name,
		}

		ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
		defer cancel()

		err := runProposalPromote(ctx, securityClient, opts, &out)
		require.NoError(t, err)

		wpProposal, err := securityClient.WorkloadPolicyProposals(ns).Get(ctx, name, metav1.GetOptions{})
		require.NoError(t, err)
		labels := wpProposal.GetLabels()
		require.NotNil(t, labels, "labels should still be present")
		require.Equal(t, "true", labels[apiv1alpha1.ApprovalLabelKey])

		output := out.String()
		require.Contains(t, output, "is already promoted to WorkloadPolicy")
	})
}
