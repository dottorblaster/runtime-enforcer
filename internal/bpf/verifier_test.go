//nolint:testpackage // we are testing unexported functions
package bpf

import (
	"testing"
)

// run it with: go test -v -run TestNoVerifierFailures ./internal/bpf -count=1 -exec "sudo -E".
func TestNoVerifierFailures(t *testing.T) {
	enableLearning := true
	// Loading happens here so we can catch verifier errors without running the manager
	_, err := NewManager(newTestLogger(t), enableLearning)
	if err == nil {
		t.Log("BPF manager started successfully :)!!")
		return
	}
	t.Log(err)
	t.FailNow()
}
