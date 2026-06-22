package e2e_test

import (
	"testing"
)

func TestMainFunctions(t *testing.T) {
	t.Log("test main functionalities")

	testEnv.Test(t, getMainTest())
}

func TestEnforcement(t *testing.T) {
	t.Log("test enforcement")

	testEnv.Test(t, getEnforcementOnNewPodsTest())
}

func TestLearning(t *testing.T) {
	t.Log("test learning")

	testEnv.Test(t, getLearningModeTest())
	testEnv.Test(t, getNoLearningModeTest())
}

func TestMonitoring(t *testing.T) {
	t.Log("test monitoring")

	testEnv.Test(t, getMonitoringTest())
}

func TestPromotion(t *testing.T) {
	t.Log("test promotion")

	testEnv.Test(t, getPromotionTest())
}

func TestPolicyUpdate(t *testing.T) {
	t.Log("test policy update")

	testEnv.Test(t, getPolicyUpdateTest())
}

func TestPolicyPerContainer(t *testing.T) {
	t.Log("test policy per container")

	testEnv.Test(t, getPolicyPerContainerTest())
}

func TestValidatingAdmissionPolicyPodPolicyLabel(t *testing.T) {
	t.Log("test ValidatingAdmissionPolicy pod policy label")

	testEnv.Test(t, getValidatingAdmissionPolicyPodPolicyLabelTest())
}

func TestRollingUpdate(t *testing.T) {
	t.Log("test rolling update")

	testEnv.Test(t, getRollingUpdateTest())
}

func TestOtelCollector(t *testing.T) {
	t.Log("test OTEL collector violation metrics")

	testEnv.Test(t, getOtelCollectorTest())
}

func TestKubectlPluginSmokeTest(t *testing.T) {
	t.Log("test kubectl plugin smoke test")

	testEnv.Test(t, getKubectlPluginSmokeTest())
}
