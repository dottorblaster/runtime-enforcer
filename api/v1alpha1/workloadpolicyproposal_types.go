package v1alpha1

import (
	"slices"

	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// policyProposalMaxExecutables defines the maximum number of executables that we can learn.
	// This is a arbitrary number right now and can be fine-tuned or made configurable in the future.
	policyProposalMaxExecutables = 100
)

// WorkloadPolicyProposalSpec defines the desired state of WorkloadPolicyProposal.
type WorkloadPolicyProposalSpec struct {

	// rulesByContainer specifies for each container the list of rules to apply.
	RulesByContainer map[string]*WorkloadPolicyRules `json:"rulesByContainer,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories={rancher-security},singular="workloadpolicyproposal",path="workloadpolicyproposals",scope="Namespaced",shortName={wpp}
// +kubebuilder:metadata:annotations="helm.sh/resource-policy=keep"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkloadPolicyProposal is the Schema for the workloadpolicyproposals API.
type WorkloadPolicyProposal struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec WorkloadPolicyProposalSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkloadPolicyProposalList contains a list of WorkloadPolicyProposal.
type WorkloadPolicyProposalList struct {
	metav1.TypeMeta `json:",inline"`

	metav1.ListMeta `json:"metadata,omitempty"`

	Items []WorkloadPolicyProposal `json:"items"`
}

func (p *WorkloadPolicyProposal) getExecutablesLength() int {
	if p.Spec.RulesByContainer == nil {
		return 0
	}

	result := 0
	for _, value := range p.Spec.RulesByContainer {
		result += len(value.Executables.Allowed)
	}

	return result
}

func (p *WorkloadPolicyProposal) NamespacedName() string {
	if p == nil {
		return ""
	}
	return p.Namespace + "/" + p.Name
}

func (p *WorkloadPolicyProposal) SetPromotionLabel() {
	if p == nil {
		return
	}
	if p.Labels == nil {
		p.SetLabels(map[string]string{})
	}
	p.Labels[ProposalPromoteLabelKey] = "true"
}

func (p *WorkloadPolicyProposal) HasPromotionLabel() bool {
	if p == nil {
		return false
	}
	return p.Labels[ProposalPromoteLabelKey] == "true"
}

func (p *WorkloadPolicyProposal) IsFull() bool {
	return p.getExecutablesLength() >= policyProposalMaxExecutables
}

func (p *WorkloadPolicyProposal) AddProcess(containerName string, executable string) {
	if p.Spec.RulesByContainer == nil {
		p.Spec.RulesByContainer = make(map[string]*WorkloadPolicyRules)
	}

	rules, ok := p.Spec.RulesByContainer[containerName]
	if !ok {
		p.Spec.RulesByContainer[containerName] = &WorkloadPolicyRules{
			Executables: WorkloadPolicyExecutables{
				Allowed: []string{executable},
			},
		}
		return
	}

	if slices.Contains(rules.Executables.Allowed, executable) {
		return
	}

	rules.Executables.Allowed = append(rules.Executables.Allowed, executable)
}

func (p *WorkloadPolicyProposal) AddPartialOwnerReferenceDetails(workloadKind string, workload string) {
	p.OwnerReferences = []metav1.OwnerReference{
		{
			Kind: workloadKind,
			Name: workload,
		},
	}
}

func (p *WorkloadPolicyProposalSpec) IntoWorkloadPolicySpec() WorkloadPolicySpec {
	// enforcement mode to "monitor" by default.
	return WorkloadPolicySpec{
		Mode:             policymode.MonitorString,
		RulesByContainer: p.RulesByContainer,
	}
}
