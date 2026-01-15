package controller_test

import (
	"context"

	"github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/controller"
	"github.com/neuvector/runtime-enforcer/internal/policygenerator"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("WorkloadPolicy Controller", func() {
	Context("When reconciling a resource", func() {
		const policyName = "test-policy"
		const testNamespace = "default"

		ctx = context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      policyName,
			Namespace: testNamespace,
		}
		policy := &v1alpha1.WorkloadPolicy{}

		BeforeEach(func() {
			By("Creating a new WorkloadPolicy that is ")
			err := k8sClient.Get(ctx, typeNamespacedName, policy)
			if err != nil && errors.IsNotFound(err) {
				resource :=
					&v1alpha1.WorkloadPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:       policyName,
							Namespace:  testNamespace,
							Finalizers: []string{v1alpha1.WorkloadPolicyFinalizer},
						},
						Spec: v1alpha1.WorkloadPolicySpec{
							Mode: "monitor",
							RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
								"main": {
									Executables: v1alpha1.WorkloadPolicyExecutables{
										Allowed: []string{"/usr/bin/sleep"},
									},
								},
							},
						},
					}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &v1alpha1.WorkloadPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if errors.IsNotFound(err) {
				// Resource already deleted, nothing to clean up
				return
			}
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance WorkloadPolicy")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})

		It("Should delete a WorkloadPolicy that is not referenced by any Pod", func() {
			By("Deleting the created WorkloadPolicy")
			policy = &v1alpha1.WorkloadPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
				},
			}
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())

			By("Reconciling the created resource")
			controllerReconciler := &controller.WorkloadPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the WorkloadPolicy has been deleted")
			err = k8sClient.Get(ctx, typeNamespacedName, policy)
			Expect(errors.IsNotFound(err)).To(BeTrue())
		})

		It("Should not delete a WorkloadPolicy that is referenced by a Pod", func() {
			By("Associating the WorkloadPolicy with a Pod")
			podName := "test-pod"
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: testNamespace,
					Labels: map[string]string{
						policygenerator.PolicyLabelKey: policyName,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "pause",
							Image: "registry.k8s.io/pause",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())

			By("Deleting the referenced WorkloadPolicy")
			policy = &v1alpha1.WorkloadPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
				},
			}
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())

			By("Reconciling the deleted WorkloadPolicy")
			controllerReconciler := &controller.WorkloadPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the WorkloadPolicy has not been deleted")
			err = k8sClient.Get(ctx, typeNamespacedName, policy)
			Expect(err).NotTo(HaveOccurred())

			By("Cleaning up the created Pod")
			Expect(k8sClient.Delete(ctx, pod)).To(Succeed())

			By("Reconciling the WorkloadPolicy deletion again")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the WorkloadPolicy has been deleted after Pod removal")
			err = k8sClient.Get(ctx, typeNamespacedName, policy)
			Expect(errors.IsNotFound(err)).To(BeTrue())
		})
	})

})
