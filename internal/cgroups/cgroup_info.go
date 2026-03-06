package cgroups

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	// CgroupSubsysCount is the max cgroup subsystems count we find in x86 vmlinux kernels.
	// See `enum cgroup_subsys_id` and value `CGROUP_SUBSYS_COUNT`.
	CgroupSubsysCount = 14

	// defaultProcFSPath is the default path to the proc filesystem.
	defaultProcFSPath = "/proc"

	// defaultCgroupMountPoint is the default mount point for cgroups.
	defaultCgroupMountPoint = defaultProcFSPath + "/1/root/sys/fs/cgroup"

	// procCgroupPath is the path to the cgroup file under the proc filesystem.
	procCgroupPath = defaultProcFSPath + "/cgroups"

	// memoryControllerName is the memory controller name.
	memoryControllerName = "memory"
)

type CgroupInfo struct {
	cgroupResolutionPrefix string
	fsMagic                uint64
	subsysV1Idx            uint32
}

var (
	cgroupInfoDetectionOnce sync.Once   //nolint:gochecknoglobals // we want it global for a global function.
	cgroupInfo              *CgroupInfo //nolint:gochecknoglobals // we want it global for a global function.
	errCgroupInfo           error
)

func GetCgroupInfo() (*CgroupInfo, error) {
	cgroupInfoDetectionOnce.Do(func() {
		cgroupInfo, errCgroupInfo = getCgroupInfo()
	})
	return cgroupInfo, errCgroupInfo
}

// GetCgroupResolutionPrefix returns the prefix used for cgroupID resolution.
// For cgroupv2 it is the cgroup mount point path. (e.g. /sys/fs/cgroup)
// For cgroupv1 it is the cgroup mount point path + the memory controller name. (e.g. /sys/fs/cgroup/memory).
func GetCgroupResolutionPrefix() string {
	cgInfo, err := GetCgroupInfo()
	if err != nil || cgInfo == nil {
		panic("cgroup info should be initialized by the bpf manager")
	}
	return cgInfo.CgroupResolutionPrefix()
}

func (c *CgroupInfo) CgroupFsMagic() uint64 {
	return c.fsMagic
}

func (c *CgroupInfo) CgroupFsMagicString() string {
	switch c.fsMagic {
	case unix.CGROUP_SUPER_MAGIC:
		return "cgroupv1"
	case unix.CGROUP2_SUPER_MAGIC:
		return "cgroupv2"
	default:
		panic("unknown cgroup fs magic")
	}
}

func (c *CgroupInfo) CgroupV1SubsysIdx() uint32 {
	return c.subsysV1Idx
}

func (c *CgroupInfo) CgroupResolutionPrefix() string {
	return c.cgroupResolutionPrefix
}

// findMemoryController returns the index of the memory controller under /proc/cgroups.
// If we don't find it we return an error.
// In cgroupv1, k8s containers could share the same cgroup under some controllers (e.g cpuset),
// but usually under the memory controller each container has its own cgroup.
func findMemoryController(path string) (uint32, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer file.Close()

	// Expected format cgroupv1:
	//
	// #subsys_name	hierarchy	num_cgroups	enabled
	// cpuset	       12	       192	       1
	// cpu	           7	       610	       1
	// cpuacct	       7	       610	       1
	// blkio	       10	       610	       1
	// memory	       13	       623	       1
	// devices	       2	       610	       1
	// freezer	       9	       193	       1
	// net_cls	       6	       192	       1
	// perf_event	   3	       192	       1
	// net_prio	       6	       192	       1
	// hugetlb	       5	       192	       1
	// pids	       	   4	       613	       1
	// rdma	           8	       192	       1
	// misc	          11	       192	       1
	//
	// We can see it from the above numbers, the `num_cgroups` for controllers like `memory` and `pids` are really high.
	// `memory` has a higher number because probably on the host there are other memory cgroups not related to k8s containers.

	// ignore first entry with fields name.
	scanner := bufio.NewScanner(file)
	scanner.Scan()
	var idx uint32
	// we save the controller names in order
	var allControllersNames []string
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return 0, fmt.Errorf("failed to parse cgroupv1 controllers: line has no fields: %s", line)
		}
		allControllersNames = append(allControllersNames, fields[0])
		idx++
		// in ebpf we don't go beyond CgroupSubsysCount so it is useless to parse more
		if idx >= CgroupSubsysCount {
			break
		}
	}

	// we want to find the index for the memory controller
	for i, name := range allControllersNames {
		if name == memoryControllerName {
			return uint32(i), nil
		}
	}

	return 0, fmt.Errorf("no '%s' controller among: %v", memoryControllerName, allControllersNames)
}

// getMountPointType returns error if the provided path is not a mount point. If it is a mount point, it returns the filesystem type.
func getMountPointType(path string) (int64, error) {
	var st, pst unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return 0, fmt.Errorf("error accessing path '%s': %w", path, err)
	}

	parent := filepath.Dir(path)
	if err := unix.Lstat(parent, &pst); err != nil {
		return 0, fmt.Errorf("error accessing parent path '%s': %w", parent, err)
	}

	// path should be a mount point if it is a cgroup root so the dev ID must differ from the parent.
	if st.Dev == pst.Dev {
		return 0, fmt.Errorf("'%s' does not appear to be a mount point", path)
	}

	fst := unix.Statfs_t{}
	if err := unix.Statfs(path, &fst); err != nil {
		return 0, fmt.Errorf("failed to get fs info for '%s'", path)
	}
	return fst.Type, nil
}

// GetCgroupInfo retrieves cgroup information such as cgroup root, fs magic and subsys index.
func getCgroupInfo() (*CgroupInfo, error) {
	// Today we don't let the user to specify a custom mount point, we just use the default one.
	// Both in cgroupv1 and cgroupv2 we should have a mount point in `defaultCgroupMountPoint`.
	// What changes is the type of the filesystem.
	fsType, err := getMountPointType(defaultCgroupMountPoint)
	if err != nil {
		return nil, fmt.Errorf("cannot get mount point type for '%s': %w", defaultCgroupMountPoint, err)
	}

	switch fsType {
	// for cgroupv2 the fs type is CGROUP2_SUPER_MAGIC
	case unix.CGROUP2_SUPER_MAGIC:
		return &CgroupInfo{
			cgroupResolutionPrefix: defaultCgroupMountPoint,
			fsMagic:                unix.CGROUP2_SUPER_MAGIC,
			subsysV1Idx:            0, // we are in v2 we don't need the index ebpf side.
		}, nil
	// for cgroupv1 or hybrid setup the fs type is TMPFS_MAGIC
	case unix.TMPFS_MAGIC:
		// If we use Cgroupv1, we need the subsys idx for ebpf.
		var idx uint32
		idx, err = findMemoryController(procCgroupPath)
		if err != nil {
			return nil, err
		}
		controllerPath := filepath.Join(defaultCgroupMountPoint, memoryControllerName)
		// we should have a mount point under this controller
		_, err = getMountPointType(controllerPath)
		if err != nil {
			return nil, fmt.Errorf("cannot get mount point type for '%s': %w", controllerPath, err)
		}
		return &CgroupInfo{
			cgroupResolutionPrefix: controllerPath,
			fsMagic:                unix.CGROUP_SUPER_MAGIC,
			subsysV1Idx:            idx,
		}, nil
	default:
		// we don't support other fs types
		return nil, fmt.Errorf("unsupported cgroup filesystem type: %d", fsType)
	}
}
