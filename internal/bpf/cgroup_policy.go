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
		return m.updateCgroupPolicy(polID, cgroupIDs, op)
	}
}

func addPolicyToCgroups(cgToPol *ebpf.Map, targetPolID uint64, cgroupIDs []uint64) error {
	if targetPolID == 0 {
		return errors.New("cannot add cgroups to policy 0")
	}

	for _, cgID := range cgroupIDs {
		// todo!: check if we can use batch operations and when they are supported
		// todo!: put in place some checks to avoid overwriting existing policies?
		if err := cgToPol.Update(&cgID, &targetPolID, ebpf.UpdateAny); err != nil {
			// we return at the first error
			return fmt.Errorf("failed to add cgroup %d to policy %d: %w", cgID, targetPolID, err)
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

	// Fiest we iterate to find all the cgroup ids associated with the target policy
	iter := cgToPol.Iterate()
	for iter.Next(&cgID, &polID) {
		if targetPolID == polID {
			cgIDList = append(cgIDList, cgID)
		}
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to iterate cgroup to policy map: %w", err)
	}

	// Now we remove all the cgroup ids associated with the target policy
	var multiErr error
	for _, cgID := range cgIDList {
		// Here all the keys should exist, so we report any error
		if err := cgToPol.Delete(&cgID); err != nil {
			multiErr = errors.Join(
				multiErr,
				fmt.Errorf("failed to remove cgroup %d from policy map: %w", cgID, err),
			)
		}
	}
	return multiErr
}

func removeCgroups(cgToPol *ebpf.Map, targetPolID uint64, cgroupIDs []uint64) error {
	if targetPolID != 0 {
		return fmt.Errorf("policy ID must be 0, got %d", targetPolID)
	}

	var multiErr error
	for _, cgID := range cgroupIDs {
		// todo!: check if we can use batch operations
		// it is possible that we call the remove just to cleanup so we ignore the ErrKeyNotExist error.
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
	// todo!: to be sure the manager is not closing the ebpf objects, we should add a mutex around this function to avoid issues at cleanup time
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
