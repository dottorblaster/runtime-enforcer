package bpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
)

func dumpMap(m *ebpf.Map) map[uint64]uint64 {
	iter := m.Iterate()
	dump := make(map[uint64]uint64)
	var key, value uint64
	for iter.Next(&key, &value) {
		dump[key] = value
	}
	return dump
}

func TestCgroupMapOperations(t *testing.T) {
	cgToPol, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8, // cgroupID
		ValueSize:  8, // policyID
		MaxEntries: 100,
	})
	require.NoError(t, err, "Failed to create test map")

	policy1 := uint64(1)
	policy2 := uint64(2)
	cgroup1 := uint64(1)
	cgroup2 := uint64(2)
	cgroup3 := uint64(3)
	cgroupKeys := []uint64{cgroup1, cgroup2, cgroup3}
	expectedMap := map[uint64]uint64{
		cgroup1: policy1,
		cgroup2: policy1,
		cgroup3: policy1,
	}

	////////////////////////
	// addPolicyToCgroups
	///////////////////////

	// We cannot use policy 0 to update cgroups
	require.Error(t, addPolicyToCgroups(cgToPol, 0, cgroupKeys))

	// We add policy to cgroups
	require.NoError(t, addPolicyToCgroups(cgToPol, policy1, cgroupKeys))
	require.Equal(t, expectedMap, dumpMap(cgToPol))

	// we try again the same operation, nothing should change.
	require.NoError(t, addPolicyToCgroups(cgToPol, policy1, cgroupKeys))
	require.Equal(t, expectedMap, dumpMap(cgToPol))

	// if we now try to bind a new policy it should fail, because cgroups are already associated.
	require.Error(t, addPolicyToCgroups(cgToPol, policy2, []uint64{cgroup2}))
	// Nothing should change.
	require.Equal(t, expectedMap, dumpMap(cgToPol))

	////////////////////////
	// removeCgroups
	///////////////////////

	// If we call with a policy != 0 we expect an error
	require.Error(t, removeCgroups(cgToPol, policy1, []uint64{cgroup1}))

	// Now we remove the cgroup1
	require.NoError(t, removeCgroups(cgToPol, 0, []uint64{cgroup1}))

	newExpectedMap := map[uint64]uint64{
		cgroup2: policy1,
		cgroup3: policy1,
	}
	require.Equal(t, newExpectedMap, dumpMap(cgToPol))

	// If we do the operation again nothing should change
	require.NoError(t, removeCgroups(cgToPol, 0, []uint64{cgroup1}))
	require.Equal(t, newExpectedMap, dumpMap(cgToPol))

	////////////////////////
	// removePolicyFromCgroups
	///////////////////////

	// There are no cgroups associated with policy2, so nothing should change
	require.NoError(t, removePolicyFromCgroups(cgToPol, policy2))
	require.Equal(t, newExpectedMap, dumpMap(cgToPol))

	// This time we remove all cgroups associated with policy1
	require.NoError(t, removePolicyFromCgroups(cgToPol, policy1))
	require.Empty(t, dumpMap(cgToPol))
}

// TestBatchOperations tests the batch operations of the cilium ebpf library not our code.
// This is a reminder on how to use batch operations.
func TestBatchOperations(t *testing.T) {
	cgToPol, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8, // cgroupID
		ValueSize:  8, // policyID
		MaxEntries: 100,
	})
	require.NoError(t, err, "Failed to create test map")

	policy1 := uint64(1)
	cgroup1 := uint64(1)
	cgroup2 := uint64(2)
	cgroup3 := uint64(3)
	cgroupSet := []uint64{cgroup1, cgroup2, cgroup3}
	values := make([]uint64, len(cgroupSet))
	for i := range cgroupSet {
		values[i] = policy1
	}

	initial := dumpMap(cgToPol)
	require.Empty(t, initial, "Map should be empty at the beginning")

	///////////////////////
	// First batch Update
	///////////////////////

	count, err := cgToPol.BatchUpdate(cgroupSet, values, &ebpf.BatchOptions{
		Flags: uint64(ebpf.UpdateAny),
	})
	require.NoError(t, err, "Batch update failed")
	require.Equal(t, len(cgroupSet), count, "Batch update did not update all entries")
	require.Equal(t, map[uint64]uint64{
		cgroup1: policy1,
		cgroup2: policy1,
		cgroup3: policy1,
	}, dumpMap(cgToPol))

	///////////////////////
	// Try UpdateNoExist
	///////////////////////

	// https://github.com/torvalds/linux/blob/1b237f190eb3d36f52dffe07a40b5eb210280e00/kernel/bpf/syscall.c#L1955
	// - `ElemFlag` can only be `BPF_F_LOCK` if the map is behind a spinLock -> We provide 0 so we call `bpf_map_update_value`
	//    https://github.com/torvalds/linux/blob/1b237f190eb3d36f52dffe07a40b5eb210280e00/kernel/bpf/syscall.c#L1989 with 0
	//    that is equivalent to `BPF_ANY`.
	// - `Flag` is not used in batch operations.
	values[0] = uint64(23)
	values[1] = uint64(24)
	values[2] = uint64(25)
	count, err = cgToPol.BatchUpdate(cgroupSet, values, &ebpf.BatchOptions{
		Flags: uint64(ebpf.UpdateNoExist),
	})
	require.NoError(t, err, "Batch update failed")
	require.Equal(t, len(cgroupSet), count, "Batch update did not update all entries")
	// even if we used UpdateNoExist, the map contains the new values
	require.Equal(t, map[uint64]uint64{
		cgroup1: uint64(23),
		cgroup2: uint64(24),
		cgroup3: uint64(25),
	}, dumpMap(cgToPol))

	///////////////////////
	// Lookup batch
	///////////////////////

	var cursor ebpf.MapBatchCursor
	lookupKeys := []uint64{cgroup1, cgroup3}
	lookupValues := make([]uint64, len(lookupKeys))
	// iterate over the buckets doesn't get the values associated with the keys.
	// https://github.com/torvalds/linux/blob/1b237f190eb3d36f52dffe07a40b5eb210280e00/kernel/bpf/hashtab.c#L1677
	count, err = cgToPol.BatchLookup(&cursor, lookupKeys, lookupValues, nil)
	require.NoError(t, err, "Batch lookup failed")
	require.Equal(t, len(lookupKeys), count, "Batch lookup did not find all entries")

	// We cannot assert the values directly since the iteration order is not guaranteed.
	//
	// require.Equal(t, lookupValues, []uint64{
	// 	uint64(23),
	// 	uint64(25),
	// }, "Batch lookup did not return expected values")

	///////////////////////
	// Delete batch on all elements
	///////////////////////

	// Also here flags are ignored https://github.com/torvalds/linux/blob/1b237f190eb3d36f52dffe07a40b5eb210280e00/kernel/bpf/syscall.c#L1889
	count, err = cgToPol.BatchDelete(cgroupSet, nil)
	require.NoError(t, err, "Batch delete failed")
	require.Equal(t, len(cgroupSet), count, "Batch delete did not delete all entries")

	// Retry it but this time cgroups do not exist anymore so we expect ErrKeyNotExist
	_, err = cgToPol.BatchDelete(cgroupSet, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
}
