package bpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

type CgroupPolicyOperation int

const (
	_ CgroupPolicyOperation = iota
	AddPolicyToCgroups
	RemovePolicy
	RemoveCgroups
)

func (op CgroupPolicyOperation) String() string {
	switch op {
	case AddPolicyToCgroups:
		return "add"
	case RemovePolicy:
		return "remove-policy"
	case RemoveCgroups:
		return "remove-cgroups"
	default:
		panic(fmt.Sprintf("unknown CgroupPolicyOperation %d", op))
	}
}

func (m *Manager) GetCgroupPolicyUpdateFunc() func(polID uint64, cgroupIDs []uint64, op CgroupPolicyOperation) error {
	return func(polID uint64, cgroupIDs []uint64, op CgroupPolicyOperation) error {
		return m.handleErrOnShutdown(m.updateCgroupPolicy(polID, cgroupIDs, op))
	}
}

func addPolicyToCgroups(cgToPol *ebpf.Map, targetPolID uint64, cgroupIDs []uint64) error {
	if targetPolID == 0 {
		return errors.New("cannot add cgroups to policy 0")
	}

	for _, cgID := range cgroupIDs {
		// Here we cannot use `BatchUpdate` because we want to detect overlapping policies.
		// https://github.com/torvalds/linux/blob/1b237f190eb3d36f52dffe07a40b5eb210280e00/kernel/bpf/syscall.c#L1955
		// - `ElemFlag` can only be `BPF_F_LOCK` if the map is behind a spinLock. Otherwise we use 0.
		//    so we call `bpf_map_update_value` https://github.com/torvalds/linux/blob/1b237f190eb3d36f52dffe07a40b5eb210280e00/kernel/bpf/syscall.c#L1989
		//    with 0 that is equivalent to `BPF_ANY`.
		// - `Flag` is not used in batch operations.
		// Since we can only use `BPF_ANY`, we cannot check for overlapping policies.
		err := cgToPol.Update(&cgID, &targetPolID, ebpf.UpdateNoExist)
		if err == nil {
			continue
		}
		if !errors.Is(err, ebpf.ErrKeyExist) {
			return fmt.Errorf("failed to add cgroup %d to policy %d: %w", cgID, targetPolID, err)
		}
		// Key exists, we need to check if the policy is the same
		var existingPolID uint64
		if err = cgToPol.Lookup(&cgID, &existingPolID); err != nil {
			return fmt.Errorf("failed to look up cgroup %d: %w", cgID, err)
		}
		if existingPolID != targetPolID {
			return fmt.Errorf(
				"cgroup %d already associated with policy %d, cannot assign policy %d: overlapping policies",
				cgID, existingPolID, targetPolID,
			)
		}
	}
	return nil
}

func removePolicyFromCgroups(cgToPol *ebpf.Map, targetPolID uint64) error {
	if targetPolID == 0 {
		return errors.New("cannot remove policy 0 from the map")
	}

	var cgID uint64
	var polID uint64
	cgIDList := []uint64{}

	// First we iterate to find all the cgroup ids associated with the target policy
	iter := cgToPol.Iterate()
	for iter.Next(&cgID, &polID) {
		if targetPolID == polID {
			cgIDList = append(cgIDList, cgID)
		}
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to iterate cgroup to policy map: %w", err)
	}

	if len(cgIDList) == 0 {
		// Nothing to remove
		return nil
	}

	// Now we remove all the cgroup ids associated with the target policy
	// In this case it's fine to use a batch operation since we already checked for existence
	// and nobody will touch the cgroup map while we are working on it.
	// The userspace is the only one that modify the map and here we are under lock.
	count, err := cgToPol.BatchDelete(cgIDList, nil)
	if err != nil || count != len(cgIDList) {
		return fmt.Errorf("failed to remove cgroups %v from policy map: %w", cgIDList, err)
	}
	return nil
}

func removeCgroups(cgToPol *ebpf.Map, targetPolID uint64, cgroupIDs []uint64) error {
	if targetPolID != 0 {
		return fmt.Errorf("policy ID must be 0, got %d", targetPolID)
	}

	var multiErr error
	for _, cgID := range cgroupIDs {
		// We cannot use `BatchDelete` because it will fail if at least one key doesn't exist.
		// This method is always called on containers deletion even if they were not associated with a policy so it's likely we will face some ErrKeyNotExist.
		if err := cgToPol.Delete(&cgID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			multiErr = errors.Join(
				multiErr,
				fmt.Errorf("failed to remove cgroup %d from policy map: %w", cgID, err),
			)
		}
	}
	return multiErr
}

func (m *Manager) updateCgroupPolicy(targetPolID uint64, cgroupIDs []uint64, op CgroupPolicyOperation) error {
	cgToPol := m.objs.CgToPolicyMap
	if cgToPol == nil {
		return errors.New("cgroup to policy map is nil")
	}

	switch op {
	case AddPolicyToCgroups:
		return addPolicyToCgroups(cgToPol, targetPolID, cgroupIDs)
	case RemovePolicy:
		return removePolicyFromCgroups(cgToPol, targetPolID)
	case RemoveCgroups:
		return removeCgroups(cgToPol, targetPolID, cgroupIDs)
	default:
		panic("unknown operation")
	}
}
