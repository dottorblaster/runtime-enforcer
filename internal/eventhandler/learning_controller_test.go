package eventhandler_test

import (
	"context"
	"fmt"

	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/eventhandler"
	"github.com/rancher-sandbox/runtime-enforcer/internal/eventscraper"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/labels"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func newTestLearningReconciler(client client.Client, selector labels.Selector) *eventhandler.LearningReconciler {
	reconciler := eventhandler.NewLearningReconciler(client, selector)
	// we don't want owner references to be added in tests because the webhook won't complete it and the api server will reject the resource creation with a partial ownerReference.
	reconciler.OwnerRefEnricher = func(_ *securityv1alpha1.WorkloadPolicyProposal, _ string, _ string) {}
	return reconciler
}

var _ = Describe("Learning", func() {
	Context("When reconciling a resource", func() {
		ctx = context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      "ubuntu-deployment",
			Namespace: "default",
		}

		proposal := &securityv1alpha1.WorkloadPolicyProposal{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deploy-ubuntu-deployment",
				Namespace: "default",
			},
			Spec: securityv1alpha1.WorkloadPolicyProposalSpec{},
		}

		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      typeNamespacedName.Name,
				Namespace: typeNamespacedName.Namespace,
			},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "ubuntu",
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Name: "ubuntu",
						Labels: map[string]string{
							"app": "ubuntu",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "ubuntu",
								Image: "ubuntu",
							},
						},
					},
				},
			},
		}

		BeforeEach(func() {
			Expect(k8sClient.Create(ctx, deployment.DeepCopy())).To(Succeed())
			Expect(k8sClient.Create(ctx, proposal.DeepCopy())).To(Succeed())
		})

		AfterEach(func() {
			Expect(k8sClient.Delete(ctx, &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      deployment.Name,
					Namespace: deployment.Namespace,
				},
			})).To(Succeed())
			Expect(k8sClient.Delete(ctx, &securityv1alpha1.WorkloadPolicyProposal{
				ObjectMeta: metav1.ObjectMeta{
					Name:      proposal.Name,
					Namespace: proposal.Namespace,
				},
			})).To(Succeed())
		})

		When("namespace selector is not specified", func() {
			It("should learn container behavior correctly", func() {
				By("appending process list without duplicate and missing")
				// In this test, we create multiple reconcilers to simulate the behavior of multiple daemons/nodes.
				// The test case here is pretty lenient to prevent tests from broken randomly.
				const workerNum = 10
				const eventsToProcessNum = 10

				eventsToProcess := []eventscraper.KubeProcessInfo{}
				expectedAllowList := []string{}

				for i := range eventsToProcessNum {
					eventsToProcess = append(eventsToProcess, eventscraper.KubeProcessInfo{
						Namespace:      "default",
						ContainerName:  "ubuntu",
						ExecutablePath: fmt.Sprintf("/usr/bin/sleep%d", i),
						Workload:       "ubuntu-deployment",
						WorkloadKind:   "Deployment",
					})
					expectedAllowList = append(expectedAllowList, fmt.Sprintf("/usr/bin/sleep%d", i))
				}

				g, groupCtx := errgroup.WithContext(ctx)

				for i := range workerNum {
					index := i
					g.Go(func() error {
						var err error
						var ret ctrl.Result
						var perWorkerClient client.Client
						name := fmt.Sprintf("worker%d", index)
						logf.Log.Info("worker started", "name", name)

						scheme := runtime.NewScheme()
						err = securityv1alpha1.AddToScheme(scheme)
						if err != nil {
							return fmt.Errorf("failed to add scheme: %w", err)
						}

						perWorkerClient, err = client.New(cfg, client.Options{
							Scheme: scheme,
						})
						if err != nil {
							return fmt.Errorf("failed to create client: %w", err)
						}

						reconciler := newTestLearningReconciler(perWorkerClient, nil)
						for _, learningEvent := range eventsToProcess {
							for {
								// with the internal ratelimiter, the learning controller would return RequeueAfter instead of a conflict error.
								ret, err = reconciler.Reconcile(groupCtx, learningEvent)
								if err == nil && ret.RequeueAfter == 0 {
									// This means the item is correctly written.
									break
								}
								if err != nil {
									return err
								}
							}
						}
						logf.Log.Info("worker finished", "name", name)
						return nil
					})
				}

				if err := g.Wait(); err != nil {
					Expect(err).NotTo(HaveOccurred())
				}

				proposalResult := securityv1alpha1.WorkloadPolicyProposal{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "deploy-ubuntu-deployment",
						Namespace: "default",
					},
				}

				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: proposalResult.Namespace,
					Name:      proposalResult.Name,
				}, &proposalResult)
				Expect(err).NotTo(HaveOccurred())

				rules := proposalResult.Spec.RulesByContainer["ubuntu"]

				Expect(rules.Executables.Allowed).To(HaveLen(eventsToProcessNum))
				Expect(rules.Executables.Allowed).To(ContainElements(expectedAllowList))
			})

			It("should correctly learn process behavior", func() {
				var err error

				const testNamespace = "default"
				const testResourceName = "ubuntu-deployment-2"
				const testProposalName = "deploy-ubuntu-deployment-2"

				tcs := []struct {
					processEvents  []eventscraper.KubeProcessInfo
					expectedResult []string
				}{
					{
						processEvents: []eventscraper.KubeProcessInfo{
							{
								Namespace:      testNamespace,
								Workload:       testResourceName,
								WorkloadKind:   "Deployment",
								ContainerName:  "ubuntu",
								ExecutablePath: "/usr/bin/sleep",
							},
							{
								Namespace:      testNamespace,
								Workload:       testResourceName,
								WorkloadKind:   "Deployment",
								ContainerName:  "ubuntu",
								ExecutablePath: "/usr/bin/bash",
							},
							{
								Namespace:      testNamespace,
								Workload:       testResourceName,
								WorkloadKind:   "Deployment",
								ContainerName:  "ubuntu",
								ExecutablePath: "/usr/bin/ls",
							},
						},
						expectedResult: []string{
							"/usr/bin/sleep",
							"/usr/bin/bash",
							"/usr/bin/ls",
						},
					},
					{
						processEvents: []eventscraper.KubeProcessInfo{
							{
								Namespace:      testNamespace,
								Workload:       testResourceName,
								WorkloadKind:   "Deployment",
								ContainerName:  "ubuntu",
								ExecutablePath: "/usr/bin/sleep",
							},
							{
								Namespace:      testNamespace,
								Workload:       testResourceName,
								WorkloadKind:   "Deployment",
								ContainerName:  "ubuntu",
								ExecutablePath: "/usr/bin/sleep",
							},
							{
								Namespace:      testNamespace,
								Workload:       testResourceName,
								WorkloadKind:   "Deployment",
								ContainerName:  "ubuntu",
								ExecutablePath: "/usr/bin/sleep",
							},
						},
						expectedResult: []string{
							"/usr/bin/sleep",
						},
					},
				}

				reconciler := newTestLearningReconciler(k8sClient, nil)

				for _, tc := range tcs {
					// Create an empty policy proposal
					testProposal := proposal.DeepCopy()
					testProposal.Namespace = testNamespace
					testProposal.Name = testProposalName
					Expect(k8sClient.Create(ctx, testProposal)).To(Succeed())

					for _, learningEvent := range tc.processEvents {
						var result ctrl.Result
						result, err = reconciler.Reconcile(ctx, learningEvent)
						Expect(err).NotTo(HaveOccurred())
						Expect(result).To(Equal(ctrl.Result{}))
					}

					err = k8sClient.Get(ctx, types.NamespacedName{
						Namespace: testNamespace,
						Name:      testProposalName,
					}, testProposal)
					Expect(err).NotTo(HaveOccurred())
					Expect(
						testProposal.Spec.RulesByContainer["ubuntu"].Executables.Allowed,
					).To(ContainElements(tc.expectedResult))

					Expect(k8sClient.Delete(ctx, &securityv1alpha1.WorkloadPolicyProposal{
						ObjectMeta: metav1.ObjectMeta{
							Name:      testProposal.Name,
							Namespace: testProposal.Namespace,
						},
					})).To(Succeed())
				}
			})

			It("should not learn process behavior when a policy proposal is labeled as ready", func() {
				const testNamespace = "default"
				const testResourceName = "ubuntu-deployment-3"
				const testProposalName = "deploy-ubuntu-deployment-3"

				var err error

				processEvents := []eventscraper.KubeProcessInfo{
					{
						Namespace:      testNamespace,
						Workload:       testResourceName,
						WorkloadKind:   "Deployment",
						ContainerName:  "ubuntu",
						ExecutablePath: "/usr/bin/sleep",
					},
					{
						Namespace:      testNamespace,
						Workload:       testResourceName,
						WorkloadKind:   "Deployment",
						ContainerName:  "ubuntu",
						ExecutablePath: "/usr/bin/bash",
					},
					{
						Namespace:      testNamespace,
						Workload:       testResourceName,
						WorkloadKind:   "Deployment",
						ContainerName:  "ubuntu",
						ExecutablePath: "/usr/bin/ls",
					},
				}

				reconciler := eventhandler.NewLearningReconciler(k8sClient, nil)

				testProposal := proposal.DeepCopy()
				testProposal.Namespace = testNamespace
				testProposal.Name = testProposalName
				labels := map[string]string{}
				labels[securityv1alpha1.ApprovalLabelKey] = "true"
				testProposal.SetLabels(labels)

				Expect(k8sClient.Create(ctx, testProposal)).To(Succeed())

				for _, learningEvent := range processEvents {
					var result ctrl.Result
					result, err = reconciler.Reconcile(ctx, learningEvent)
					Expect(err).NotTo(HaveOccurred())
					Expect(result).To(Equal(ctrl.Result{}))
				}

				err = k8sClient.Get(ctx, types.NamespacedName{
					Namespace: testNamespace,
					Name:      testProposalName,
				}, testProposal)
				Expect(err).NotTo(HaveOccurred())
				Expect(testProposal.Spec.RulesByContainer).To(BeNil())

				Expect(k8sClient.Delete(ctx, &securityv1alpha1.WorkloadPolicyProposal{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testProposal.Name,
						Namespace: testProposal.Namespace,
					},
				})).To(Succeed())
			})
		})

		When("namespace selector is specified", func() {
			When("namespace does not match selector", func() {
				It("should skip reconciliation and not create resources", func(ctx context.Context) {
					By("Creating a reconciler with a namespace selector")
					selector := labels.Set{
						"env": "testing",
					}.AsSelector()
					reconciler := newTestLearningReconciler(k8sClient, selector)

					By("Creating a namespace that does not match the selector")
					namespace := &corev1.Namespace{
						ObjectMeta: metav1.ObjectMeta{
							Name: "unmatched-namespace",
							Labels: map[string]string{
								"env": "development",
							},
						},
					}
					Expect(k8sClient.Create(ctx, namespace)).To(Succeed())

					By("Reconciling a namespace that does not match the selector")
					_, err := reconciler.Reconcile(ctx, eventscraper.KubeProcessInfo{
						Namespace:      namespace.Name,
						Workload:       deployment.Name,
						WorkloadKind:   "Deployment",
						ContainerName:  "ubuntu",
						ExecutablePath: "/usr/bin/sleep",
					})
					Expect(err).NotTo(HaveOccurred())

					By("Verifying no WorkloadPolicyProposal is created")
					var proposalList securityv1alpha1.WorkloadPolicyProposalList
					Expect(k8sClient.List(ctx, &proposalList, client.InNamespace(namespace.Name))).To(Succeed())
					Expect(proposalList.Items).To(BeEmpty())

					Expect(k8sClient.Delete(ctx, namespace)).To(Succeed())
				})
			})

			When("namespace matches selector", func() {
				It("should create WorkloadPolicyProposal and learn process behavior", func(ctx context.Context) {
					By("Creating a reconciler with a namespace selector")
					selector := labels.Set{
						"env": "testing",
					}.AsSelector()
					reconciler := newTestLearningReconciler(k8sClient, selector)

					By("Creating a namespace that matches the selector")
					namespace := &corev1.Namespace{
						ObjectMeta: metav1.ObjectMeta{
							Name: "matched-namespace",
							Labels: map[string]string{
								"env": "testing",
							},
						},
					}
					Expect(k8sClient.Create(ctx, namespace)).To(Succeed())
					By("Reconciling a namespace that matches the selector")
					_, err := reconciler.Reconcile(ctx, eventscraper.KubeProcessInfo{
						Namespace:      namespace.Name,
						Workload:       deployment.Name,
						WorkloadKind:   "Deployment",
						ContainerName:  "ubuntu",
						ExecutablePath: "/usr/bin/sleep",
					})
					Expect(err).NotTo(HaveOccurred())

					By("Verifying WorkloadPolicyProposal is created")
					var proposalList securityv1alpha1.WorkloadPolicyProposalList
					Expect(k8sClient.List(ctx, &proposalList, client.InNamespace(namespace.Name))).To(Succeed())
					Expect(proposalList.Items).To(HaveLen(1))
					Expect(proposalList.Items[0].Spec.RulesByContainer).To(HaveKey("ubuntu"))
					Expect(
						proposalList.Items[0].Spec.RulesByContainer["ubuntu"].Executables.Allowed,
					).To(ContainElement("/usr/bin/sleep"))

					Expect(k8sClient.Delete(ctx, namespace)).To(Succeed())
				})
			})
		})
	})
})
