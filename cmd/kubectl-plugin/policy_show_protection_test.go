package main

import (
	"bytes"
	"encoding/json"
	"testing"

	apiv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidatePolicyShowProtectionOutput(t *testing.T) {
	t.Parallel()

	require.NoError(t, validatePolicyShowProtectionOutput(policyShowProtectionOutputTable))
	require.NoError(t, validatePolicyShowProtectionOutput(policyShowProtectionOutputJSON))
	require.Error(t, validatePolicyShowProtectionOutput("yaml"))
}

func TestBuildPolicyProtectionRows(t *testing.T) {
	t.Parallel()

	namespaceA := "ns-a"
	namespaceB := "ns-b"
	podA := "pod-a"
	podB := "pod-b"
	policyA := "policy-a"

	tests := []struct {
		name     string
		pods     []corev1.Pod
		policies []apiv1alpha1.WorkloadPolicy
		expected []policyProtectionRow
	}{
		{
			name: "2 pods protected by the same policy",
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podA,
						Namespace: namespaceA,
						Labels: map[string]string{
							apiv1alpha1.PolicyLabelKey: policyA,
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podB,
						Namespace: namespaceA,
						Labels: map[string]string{
							apiv1alpha1.PolicyLabelKey: policyA,
						},
					},
				},
			},
			policies: []apiv1alpha1.WorkloadPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      policyA,
						Namespace: namespaceA,
					},
				},
			},
			expected: []policyProtectionRow{
				{Pod: namespacedName(namespaceA, podA), Policy: policyA, PolicyExists: true},
				{Pod: namespacedName(namespaceA, podB), Policy: policyA, PolicyExists: true},
			},
		},
		{
			name: "Missing policy",
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podA,
						Namespace: namespaceA,
						Labels: map[string]string{
							apiv1alpha1.PolicyLabelKey: policyA,
						},
					},
				},
				{
					// This pod has no policies so it should not be included in the output
					ObjectMeta: metav1.ObjectMeta{
						Name:      podB,
						Namespace: namespaceA,
						Labels:    map[string]string{},
					},
				},
			},
			policies: nil,
			expected: []policyProtectionRow{
				{Pod: namespacedName(namespaceA, podA), Policy: policyA, PolicyExists: false},
			},
		},
		{
			name: "2 policies same name but different namespace",
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podA,
						Namespace: namespaceA,
						Labels: map[string]string{
							apiv1alpha1.PolicyLabelKey: policyA,
						},
					},
				},
			},
			policies: []apiv1alpha1.WorkloadPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      policyA,
						Namespace: namespaceA,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      policyA,
						Namespace: namespaceB,
					},
				},
			},
			expected: []policyProtectionRow{
				{Pod: namespacedName(namespaceA, podA), Policy: policyA, PolicyExists: true},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rows := buildPolicyProtectionRows(tc.pods, tc.policies)
			require.Len(t, rows, len(tc.expected))
			for i := range rows {
				// the slice is ordered so we can compare directly
				require.Equal(t, tc.expected[i], rows[i])
			}
		})
	}
}

func TestRenderPolicyProtectionJSONIncludesFields(t *testing.T) {
	t.Parallel()

	rows := []policyProtectionRow{{Pod: "ns-a/pod-a", Policy: "policy-a", PolicyExists: true}}
	var out bytes.Buffer

	err := renderPolicyProtectionJSON(&out, rows)
	require.NoError(t, err)

	var decoded []map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &decoded))
	require.Len(t, decoded, 1)
	require.Equal(t, "ns-a/pod-a", decoded[0]["pod"])
	require.Equal(t, "policy-a", decoded[0]["policy"])
	require.Equal(t, true, decoded[0]["policyExists"])
}

func TestRenderPolicyProtectionTableIncludesMissingIndicator(t *testing.T) {
	t.Parallel()

	rows := []policyProtectionRow{
		{Pod: "ns-a/pod-a", Policy: "policy-a", PolicyExists: true},
		{Pod: "ns-a/pod-b", Policy: "policy-b", PolicyExists: false},
	}

	var out bytes.Buffer
	err := renderPolicyProtectionTable(&out, rows)
	require.NoError(t, err)

	output := out.String()
	require.Contains(t, output, "ns-a/pod-a")
	require.Contains(t, output, "ns-a/pod-b")
	require.Contains(t, output, missingPolicyIndicator)
	require.Contains(t, output, missingPolicyMessage)
}
