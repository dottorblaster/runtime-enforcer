package resolver

import (
	"context"
	"log/slog"
	"sync"

	"github.com/neuvector/runtime-enforcer/internal/bpf"
	"github.com/neuvector/runtime-enforcer/internal/types/policymode"
)

type CgroupID = uint64
type ContainerID = string
type PodID = string
type ContainerName = string

type Resolver struct {
	// let's see if we can split this unique lock in multiple locks later
	mu     sync.Mutex
	logger *slog.Logger
	// todo!: we should add a cache with deleted pods/containers so that we can resolve also recently deleted ones
	podCache        map[PodID]*podState
	cgroupIDToPodID map[CgroupID]PodID

	nextPolicyID                PolicyID
	wpState                     map[namespacedPolicyName]policyByContainer
	policyUpdateBinariesFunc    func(policyID PolicyID, values []string, op bpf.PolicyValuesOperation) error
	policyModeUpdateFunc        func(policyID PolicyID, mode policymode.Mode, op bpf.PolicyModeOperation) error
	cgTrackerUpdateFunc         func(cgID uint64, cgroupPath string) error
	cgroupToPolicyMapUpdateFunc func(polID PolicyID, cgroupIDs []CgroupID, op bpf.CgroupPolicyOperation) error
}

func NewResolver(
	_ context.Context,
	logger *slog.Logger,
	cgTrackerUpdateFunc func(cgID uint64, cgroupPath string) error,
	cgroupToPolicyMapUpdateFunc func(polID PolicyID, cgroupIDs []CgroupID, op bpf.CgroupPolicyOperation) error,
	policyUpdateBinariesFunc func(policyID uint64, values []string, op bpf.PolicyValuesOperation) error,
	policyModeUpdateFunc func(policyID uint64, mode policymode.Mode, op bpf.PolicyModeOperation) error,
) (*Resolver, error) {
	r := &Resolver{
		logger:                      logger.With("component", "resolver"),
		podCache:                    make(map[PodID]*podState),
		cgroupIDToPodID:             make(map[CgroupID]PodID),
		cgTrackerUpdateFunc:         cgTrackerUpdateFunc,
		cgroupToPolicyMapUpdateFunc: cgroupToPolicyMapUpdateFunc,
		policyUpdateBinariesFunc:    policyUpdateBinariesFunc,
		policyModeUpdateFunc:        policyModeUpdateFunc,
		wpState:                     make(map[namespacedPolicyName]policyByContainer),
		nextPolicyID:                PolicyID(1),
	}

	// todo!: we can do a first scan of all existing containers to populate the cache initially
	return r, nil
}
