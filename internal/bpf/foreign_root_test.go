package bpf

import (
	"testing"
)

// TestForeignRootExec documents the coverage of vector A. Vector A uses procfs
// magic links into a foreign root, for example /proc/1/root/<allowed>. A true
// test of this vector needs a container root file system with a superblock that
// differs from the host. The current test harness runs directly on the host file
// system. It does not give such a root file system. A true test needs a separate,
// minimal root file system. The process must enter it with pivot_root. Then
// /proc/1/root points to a foreign superblock.
//
// Manual reproduction:
//  1. Use a privileged container with hostPID. Allow-list only the container
//     entrypoint, for example /service.
//  2. From inside the container, exec /proc/1/root/service. This is the /service
//     file of the host.
//  3. The mount namespace of the file is the host namespace. It differs from the
//     mount namespace of the container task. Therefore the enforcer classifies
//     the exec as a foreign root. The enforcer reports it with a violation event
//     and sets the foreign flag on the event. The enforcer denies it in protect
//     mode.
//  4. Set the ALLOW_FOREIGN_ROOT_EXEC option to "1" for that container in the
//     WorkloadPolicy. The same exec then succeeds. The enforcer skips the
//     foreign-root check for the policy id of the container. See the
//     allow_foreign_root field of policy_settings_map. The test
//     resolver.TestReconcileWP_AllowForeignRootExec covers the Go wiring for this
//     option.
func TestForeignRootExec(t *testing.T) {
	t.Skip("vector A requires a separate container rootfs (pivot_root); see test doc for manual repro")
}
