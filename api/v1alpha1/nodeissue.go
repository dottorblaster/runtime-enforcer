package v1alpha1

// NodeIssueCode represents the code for a node issue.
type NodeIssueCode string

const (
	NodeIssueNone          NodeIssueCode = "None"
	NodeIssuePodNotReady   NodeIssueCode = "PodNotReady"
	NodeIssueMissingPolicy NodeIssueCode = "MissingPolicy"
	NodeIssuePolicyFailed  NodeIssueCode = "PolicyFailed"
	NodeIssueMaxReached    NodeIssueCode = "MaxReached"

	TruncationNodeString = "..."
)

// NodeIssue represents an issue with a node.
type NodeIssue struct {
	// code is the issue code.
	Code NodeIssueCode `json:"code,omitempty"`
	// message is a human-readable description of the issue.
	Message string `json:"message,omitempty"`
}
