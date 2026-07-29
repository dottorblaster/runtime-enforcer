package v1alpha1

const (
	// ProposalPromoteLabelKey is set on a WorkloadPolicyProposal when it is promoted to a WorkloadPolicy.
	// Valid values are policymode strings ("monitor", "protect"). The value "true" is accepted as an
	// alias for "monitor" for backward compatibility.
	ProposalPromoteLabelKey = "security.rancher.io/promote"

	// ProposalPromoteLabelTrueAlias is the legacy promote label value, treated as "monitor" mode.
	ProposalPromoteLabelTrueAlias = "true"

	// PolicyPromotedFromLabelKey is set on a WorkloadPolicy when it is created by
	// promoting a WorkloadPolicyProposal.
	// The learning controller uses it to avoid recreating proposals for
	// workloads that are already protected by an existing policy.
	PolicyPromotedFromLabelKey = "security.rancher.io/promoted-from"

	// PolicyLabelKey is set on a Workload to identify to bind it to a specific policy.
	PolicyLabelKey = "security.rancher.io/policy"

	// ViolationAcknowledgePrefix is the prefix of annotation key used to acknowledge a violation.
	ViolationAcknowledgePrefix = "security.rancher.io/acknowledge-"
)
