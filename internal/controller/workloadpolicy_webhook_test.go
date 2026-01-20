package controller_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/controller"
	"github.com/neuvector/runtime-enforcer/internal/types/policymode"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var _ = Describe("WorkloadPolicy Webhook", func() {
	Context("When creating a WorkloadPolicy", func() {
		It("should add finalizer on CREATE", func() {
			By("creating a policy without finalizer")

			policy := &v1alpha1.WorkloadPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: v1alpha1.WorkloadPolicySpec{
					Mode: policymode.MonitorString,
					RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
						"container1": {
							Executables: v1alpha1.WorkloadPolicyExecutables{
								Allowed: []string{"/usr/bin/sleep"},
							},
						},
					},
				},
			}

			webhook := &controller.PolicyWebhook{}
			err := webhook.Default(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			Expect(controllerutil.ContainsFinalizer(policy, v1alpha1.WorkloadPolicyFinalizer)).To(BeTrue())
			Expect(policy.Finalizers).To(ContainElement(v1alpha1.WorkloadPolicyFinalizer))
		})

		It("should be idempotent - not add duplicate finalizer", func() {
			By("creating a policy with finalizer already present")

			policy := &v1alpha1.WorkloadPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-policy-idempotent",
					Namespace:  "default",
					Finalizers: []string{v1alpha1.WorkloadPolicyFinalizer},
				},
				Spec: v1alpha1.WorkloadPolicySpec{
					Mode: policymode.MonitorString,
					RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
						"container1": {
							Executables: v1alpha1.WorkloadPolicyExecutables{
								Allowed: []string{"/usr/bin/sleep"},
							},
						},
					},
				},
			}

			initialFinalizerCount := len(policy.Finalizers)

			webhook := &controller.PolicyWebhook{}
			err := webhook.Default(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			Expect(policy.Finalizers).To(HaveLen(initialFinalizerCount))
			Expect(policy.Finalizers).To(ContainElement(v1alpha1.WorkloadPolicyFinalizer))
		})

		It("should add finalizer even when other finalizers exist", func() {
			By("creating a policy with other finalizers")

			policy := &v1alpha1.WorkloadPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-policy-multiple-finalizers",
					Namespace:  "default",
					Finalizers: []string{"other-finalizer"},
				},
				Spec: v1alpha1.WorkloadPolicySpec{
					Mode: policymode.ProtectString,
					RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
						"container1": {
							Executables: v1alpha1.WorkloadPolicyExecutables{
								Allowed: []string{"/usr/bin/sleep"},
							},
						},
					},
				},
			}

			webhook := &controller.PolicyWebhook{}
			err := webhook.Default(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			Expect(policy.Finalizers).To(ContainElement("other-finalizer"))
			Expect(policy.Finalizers).To(ContainElement(v1alpha1.WorkloadPolicyFinalizer))
			Expect(policy.Finalizers).To(HaveLen(2))
		})
	})
})
