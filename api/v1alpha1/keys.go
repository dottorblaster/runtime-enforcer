package v1alpha1

const (
	// ProposalPromoteLabelKey is set on a WorkloadPolicyProposal when it is promoted to a WorkloadPolicy.
	ProposalPromoteLabelKey = "security.rancher.io/promote"

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
