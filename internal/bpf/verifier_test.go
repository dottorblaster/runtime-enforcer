//nolint:testpackage // we are testing unexported functions
package bpf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

// run it with: go test -v -run TestNoVerifierFailures ./internal/bpf -count=1 -exec "sudo -E".
func TestNoVerifierFailures(t *testing.T) {
	enableLearning := true
	// Loading happens here so we can catch verifier errors without running the manager
	_, err := NewManager(newTestLogger(t), enableLearning, ebpf.LogLevelBranch)
	if err == nil {
		t.Log("BPF manager started successfully :)!!")
		return
	}
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		t.Log("Verifier errors detected:")
		for _, log := range verr.Log {
			t.Log(log)
		}
	}
	t.Log(err)
	t.FailNow()
}
