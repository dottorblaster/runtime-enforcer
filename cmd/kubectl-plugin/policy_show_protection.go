package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	apiv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	securityclient "github.com/rancher-sandbox/runtime-enforcer/pkg/generated/clientset/versioned/typed/api/v1alpha1"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/cli-runtime/pkg/printers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

const (
	policyShowProtectionOutputTable = "table"
	policyShowProtectionOutputJSON  = "json"

	missingPolicyIndicator = "❌"
	missingPolicyMessage   = "policy does not exist"
)

type policyShowProtectionOptions struct {
	commonOptions

	Output        string
	AllNamespaces bool
}

type policyProtectionRow struct {
	Pod          string `json:"pod"`
	Policy       string `json:"policy"`
	PolicyExists bool   `json:"policyExists"`
}

func newPolicyShowProtectionCmd() *cobra.Command {
	opts := &policyShowProtectionOptions{
		commonOptions: newCommonOptions(),
		Output:        policyShowProtectionOutputTable,
	}

	cmd := &cobra.Command{
		Use:   "protection",
		Short: "List pod to WorkloadPolicy protection mapping",
		Args:  cobra.NoArgs,
		RunE:  runPolicyShowProtectionCmd(opts),
	}

	cmd.SetUsageTemplate(subcommandUsageTemplate)

	// Standard kube flags (adds --namespace, --kubeconfig, --context, etc.)
	opts.configFlags.AddFlags(cmd.Flags())

	cmd.Flags().StringVarP(
		&opts.Output,
		"output",
		"o",
		policyShowProtectionOutputTable,
		"Output format. One of: table|json",
	)
	cmd.Flags().BoolVarP(
		&opts.AllNamespaces,
		"all-namespaces",
		"A",
		false,
		"If present, list requested object(s) across all namespaces",
	)

	return cmd
}

func runPolicyShowProtectionCmd(opts *policyShowProtectionOptions) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		if err := validatePolicyShowProtectionOutput(opts.Output); err != nil {
			return err
		}

		return withRuntimeEnforcerAndCoreClient(cmd, &opts.commonOptions, func(
			ctx context.Context,
			securityClient securityclient.SecurityV1alpha1Interface,
			coreClient corev1client.CoreV1Interface,
		) error {
			return runPolicyShowProtection(ctx, securityClient, coreClient, opts, opts.ioStreams.Out)
		})
	}
}

func runPolicyShowProtection(
	ctx context.Context,
	securityClient securityclient.SecurityV1alpha1Interface,
	coreClient corev1client.CoreV1Interface,
	opts *policyShowProtectionOptions,
	out io.Writer,
) error {
	rows, err := collectPolicyProtectionRows(ctx, securityClient, coreClient, opts)
	if err != nil {
		return err
	}

	if len(rows) == 0 {
		fmt.Fprintln(out, "No pods protected by a policy")
		return nil
	}

	if opts.Output == policyShowProtectionOutputJSON {
		return renderPolicyProtectionJSON(out, rows)
	}

	return renderPolicyProtectionTable(out, rows)
}

func collectPolicyProtectionRows(
	ctx context.Context,
	securityClient securityclient.SecurityV1alpha1Interface,
	coreClient corev1client.CoreV1Interface,
	opts *policyShowProtectionOptions,
) ([]policyProtectionRow, error) {
	// - If the user doesn't specify a namespace, use the current namespace taken from the kubeconfig
	// - If the user specifies --namespace, use the specified namespace
	// - If the user specifies --all-namespaces, use the wildcard namespace
	namespace := opts.Namespace
	if opts.AllNamespaces {
		namespace = metav1.NamespaceAll
	}

	pods, err := coreClient.Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list Pods in namespace %q: %w", namespace, err)
	}

	workloadPolicies, err := securityClient.WorkloadPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list WorkloadPolicies in namespace %q: %w", namespace, err)
	}

	return buildPolicyProtectionRows(pods.Items, workloadPolicies.Items), nil
}

func validatePolicyShowProtectionOutput(output string) error {
	switch output {
	case policyShowProtectionOutputTable, policyShowProtectionOutputJSON:
		return nil
	default:
		return fmt.Errorf("invalid output %q, expected %q or %q",
			output,
			policyShowProtectionOutputTable,
			policyShowProtectionOutputJSON,
		)
	}
}

func namespacedName(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

func buildPolicyProtectionRows(pods []corev1.Pod, workloadPolicies []apiv1alpha1.WorkloadPolicy) []policyProtectionRow {
	type policyNamespacedName = string

	activePolicies := sets.New[policyNamespacedName]()
	for _, policy := range workloadPolicies {
		activePolicies.Insert(policy.NamespacedName())
	}

	rows := make([]policyProtectionRow, 0)
	for _, pod := range pods {
		policyName := pod.Labels[apiv1alpha1.PolicyLabelKey]
		// if there is no policy label we don't consider the pod
		if policyName == "" {
			continue
		}

		podKey := namespacedName(pod.Namespace, pod.Name)
		rows = append(rows, policyProtectionRow{
			Pod: podKey,
			// this is not the namespaced name of the policy.
			Policy: policyName,
			// if the policy doesn't exist in the cluster, we mark it as missing
			// the namespace of the policy is the same of the pod.
			PolicyExists: activePolicies.Has(namespacedName(pod.Namespace, policyName)),
		})
	}

	slices.SortFunc(rows, func(a, b policyProtectionRow) int {
		if a.Pod < b.Pod {
			return -1
		}
		if a.Pod > b.Pod {
			return 1
		}
		return 0
	})

	return rows
}

func renderPolicyProtectionTable(out io.Writer, rows []policyProtectionRow) error {
	printer := printers.NewTablePrinter(printers.PrintOptions{})
	table := &metav1.Table{
		ColumnDefinitions: []metav1.TableColumnDefinition{
			{Name: "POD", Type: "string", Format: "name", Description: "Pod name"},
			{Name: "WORKLOAD POLICY", Type: "string", Description: "Associated WorkloadPolicy"},
		},
		Rows: make([]metav1.TableRow, 0, len(rows)),
	}

	for _, row := range rows {
		policyText := row.Policy
		if !row.PolicyExists {
			policyText = fmt.Sprintf("%s (%s %s)", row.Policy, missingPolicyIndicator, missingPolicyMessage)
		}

		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []any{row.Pod, policyText},
		})
	}

	if err := printer.PrintObj(table, out); err != nil {
		return fmt.Errorf("failed to write table output: %w", err)
	}

	return nil
}

func renderPolicyProtectionJSON(out io.Writer, rows []policyProtectionRow) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(rows); err != nil {
		return fmt.Errorf("failed to write JSON output: %w", err)
	}

	return nil
}
