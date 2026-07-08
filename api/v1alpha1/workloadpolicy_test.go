package v1alpha1_test

import (
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWorkloadPolicyNamespacedName(t *testing.T) {
	wp := &v1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-namespace",
			Name:      "test-name",
		},
	}
	expected := "test-namespace/test-name"
	require.Equal(t, expected, wp.NamespacedName())
}
