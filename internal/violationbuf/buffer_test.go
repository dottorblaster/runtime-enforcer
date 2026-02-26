package violationbuf_test

import (
	"fmt"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/internal/violationbuf"
	"github.com/stretchr/testify/require"
)

func TestBufferRecordAndDrain(t *testing.T) {
	buf := violationbuf.NewBuffer()

	buf.Record(violationbuf.ViolationInfo{
		PolicyName:    "pol1",
		Namespace:     "ns1",
		PodName:       "pod1",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})

	records := buf.Drain()
	require.Len(t, records, 1)
	require.Equal(t, "pol1", records[0].PolicyName)
	require.Equal(t, "ns1", records[0].Namespace)
	require.Equal(t, uint32(1), records[0].Count)

	// After drain, buffer should be empty.
	records = buf.Drain()
	require.Empty(t, records)
}

func TestBufferDeduplication(t *testing.T) {
	buf := violationbuf.NewBuffer()

	info := violationbuf.ViolationInfo{
		PolicyName:    "pol1",
		Namespace:     "ns1",
		PodName:       "pod1",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	}

	buf.Record(info)
	buf.Record(info)
	buf.Record(info)

	records := buf.Drain()
	require.Len(t, records, 1)
	require.Equal(t, uint32(3), records[0].Count)
}

func TestBufferCapDropsNewKeys(t *testing.T) {
	buf := violationbuf.NewBuffer()

	// Fill the buffer to its max capacity with unique keys.
	for i := range violationbuf.MaxBufferEntries {
		buf.Record(violationbuf.ViolationInfo{
			PolicyName:    fmt.Sprintf("pol-%d", i),
			Namespace:     "ns1",
			PodName:       "pod1",
			ContainerName: "ctr1",
			ExePath:       "/bin/sh",
			NodeName:      "node1",
			Action:        "monitor",
		})
	}
	require.Equal(t, uint64(0), buf.Dropped())

	// One more unique key should be dropped.
	buf.Record(violationbuf.ViolationInfo{
		PolicyName:    "pol-overflow",
		Namespace:     "ns1",
		PodName:       "pod1",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})
	require.Equal(t, uint64(1), buf.Dropped())

	// Existing keys should still be updated (count incremented, not dropped).
	buf.Record(violationbuf.ViolationInfo{
		PolicyName:    "pol-0",
		Namespace:     "ns1",
		PodName:       "pod1",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})
	require.Equal(t, uint64(1), buf.Dropped(), "updating existing key should not increment dropped")

	records := buf.Drain()
	require.Len(t, records, violationbuf.MaxBufferEntries)
	require.Equal(t, uint64(0), buf.Dropped(), "drain should reset dropped counter")
}

func TestBufferDifferentKeys(t *testing.T) {
	buf := violationbuf.NewBuffer()

	buf.Record(violationbuf.ViolationInfo{
		PolicyName:    "pol1",
		Namespace:     "ns1",
		PodName:       "pod1",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})

	buf.Record(violationbuf.ViolationInfo{
		PolicyName:    "pol1",
		Namespace:     "ns1",
		PodName:       "pod2",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})

	records := buf.Drain()
	require.Len(t, records, 2)
}
