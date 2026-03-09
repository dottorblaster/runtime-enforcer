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

func TestRunMarkReadyUpdatesLabelAndWaitsForPolicy(t *testing.T) {
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
	opts := &markReadyOptions{
		PolicyName: name,
		Namespace:  ns,
		DryRun:     false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), markReadyTimeout)
	defer cancel()

	err := runMarkReady(ctx, securityClient, opts, &out)
	require.NoError(t, err)

	wpProposal, err := securityClient.WorkloadPolicyProposals(ns).Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)

	labels := wpProposal.GetLabels()
	require.NotNil(t, labels, "labels should be set after promotion")
	require.Equal(t, "true", labels[apiv1alpha1.ApprovalLabelKey])

	output := out.String()
	require.Contains(t, output, "Marked WorkloadPolicyProposal \"test-deployment\" in namespace \"test\" as ready.")
	require.Contains(t, output, "WorkloadPolicy \"test-deployment\" in namespace \"test\" has been created.")
}
