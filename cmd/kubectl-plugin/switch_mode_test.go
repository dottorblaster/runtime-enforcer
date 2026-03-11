package main

import (
	"bytes"
	"context"
	"testing"

	apiv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	fakeclient "github.com/rancher-sandbox/runtime-enforcer/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRunSwitchModeMonitorToProtect(t *testing.T) {
	t.Parallel()

	ns := "test"
	name := "test-policy"

	policy := &apiv1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: apiv1alpha1.WorkloadPolicySpec{
			Mode: "monitor",
		},
	}

	clientset := fakeclient.NewClientset(policy)
	securityClient := clientset.SecurityV1alpha1()

	var out bytes.Buffer
	opts := &switchModeOptions{
		commonOptions: commonOptions{
			Namespace: ns,
			DryRun:    false,
		},
		PolicyName: name,
		Mode:       policymode.ProtectString,
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()

	err := runSwitchMode(ctx, securityClient, opts, &out)
	require.NoError(t, err)

	updatedPolicy, err := securityClient.WorkloadPolicies(ns).Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, policymode.ProtectString, updatedPolicy.Spec.Mode)

	output := out.String()
	require.Contains(
		t,
		output,
		"Successfully switched WorkloadPolicy \"test-policy\" in namespace \"test\" from \"monitor\" mode to \"protect\" mode.",
	)
}

func TestRunSwitchModeProtectToMonitor(t *testing.T) {
	t.Parallel()

	ns := "test"
	name := "test-policy"

	policy := &apiv1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: apiv1alpha1.WorkloadPolicySpec{
			Mode: "protect",
		},
	}

	clientset := fakeclient.NewClientset(policy)
	securityClient := clientset.SecurityV1alpha1()

	var out bytes.Buffer
	opts := &switchModeOptions{
		commonOptions: commonOptions{
			Namespace: ns,
			DryRun:    false,
		},
		PolicyName: name,
		Mode:       policymode.MonitorString,
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()

	err := runSwitchMode(ctx, securityClient, opts, &out)
	require.NoError(t, err)

	updatedPolicy, err := securityClient.WorkloadPolicies(ns).Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, policymode.MonitorString, updatedPolicy.Spec.Mode)

	output := out.String()
	require.Contains(
		t,
		output,
		"Successfully switched WorkloadPolicy \"test-policy\" in namespace \"test\" from \"protect\" mode to \"monitor\" mode.",
	)
}
