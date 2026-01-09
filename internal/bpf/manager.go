package bpf

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/neuvector/runtime-enforcer/internal/cgroups"
	"github.com/neuvector/runtime-enforcer/internal/kernels"

	"golang.org/x/sync/errgroup"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g" -target native -tags linux -type process_evt bpf ../../bpf/main.c -- -I/usr/include/

const (
	loadTimeConfigBPFVar = "load_time_config"
	policyMap8Name       = "pol_str_maps_8"
	policyMap9Name       = "pol_str_maps_9"
	policyMap10Name      = "pol_str_maps_10"
)

const (
	// 100 should be enough to avoid blocking in normal conditions, let's monitor this later.
	learningEventChanSize = 100
	monitorEventChanSize  = 100
)

// ProcessEvent represents an event coming from BPF programs, for now used for learning and monitoring.
type ProcessEvent struct {
	CgroupID    uint64
	CgTrackerID uint64
	ExePath     string
	Mode        string
}

type bpfEventHeader struct {
	Cgid        uint64
	CgTrackerID uint64
	PathLen     uint16
	Mode        uint8
}

type Manager struct {
	logger           *slog.Logger
	objs             *bpfObjects
	policyStringMaps []*ebpf.Map

	// Learning
	enableLearning    bool
	learningEventChan chan ProcessEvent

	// Monitoring
	monitoringEventChan chan ProcessEvent

	// Kernel version check cache
	kernelCheckOnce sync.Once
	isPre5_9        bool
}

func probeEbpfFeatures() error {
	// For now known requirements are:
	// - BPF_MAP_TYPE_RINGBUF
	// - tracing prog with attach type BPF_MODIFY_RETURN

	// Check for BPF_MAP_TYPE_RINGBUF
	if err := features.HaveMapType(ebpf.RingBuf); err != nil {
		return fmt.Errorf("BPF_MAP_TYPE_RINGBUF not supported: %w", err)
	}

	// Check for BPF_MODIFY_RETURN attach type
	// Today there is no an helper function for attach type BPF_MODIFY_RETURN so we do it by hand.
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "probe_fmodret",
		Type: ebpf.Tracing,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachModifyReturn,
		License:    "MIT",
		AttachTo:   "security_bprm_creds_for_exec",
	})
	if err != nil {
		return err
	}
	defer prog.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		return err
	}
	err = link.Close()
	if err != nil {
		return err
	}

	return nil
}

func NewManager(logger *slog.Logger, enableLearning bool, eBPFLogLevel ebpf.LogLevel) (*Manager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %w", err)
	}

	logger.Info("Probing eBPF features...")
	if err := probeEbpfFeatures(); err != nil {
		return nil, fmt.Errorf("failure during eBPF feature probing: %w", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("failed to load BPF spec: %w", err)
	}

	conf, err := getLoadTimeConfig(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to get load time config: %w", err)
	}

	if err = spec.Variables[loadTimeConfigBPFVar].Set(conf); err != nil {
		return nil, fmt.Errorf("error rewriting load_time_config: %w", err)
	}

	newLogger := logger.With("component", "ebpf-manager")
	newLogger.Info("Load time configuration detected",
		"cgrp_fs_magic", cgroups.CgroupFsMagicString(conf.CgrpFsMagic),
		"cgrp_v1_subsys_idx", conf.Cgrpv1SubsysIdx,
		"debug_mode", conf.DebugMode)

	// Only kernels >= 5.11 support hash key lengths > 512 bytes
	// https://github.com/cilium/tetragon/commit/834b5fe7d4063928cf7b89f61252637d833ca018
	// so we reduce the key size for older kernels, these maps won't be used anyway
	if kernels.CurrVersionIsLowerThan("5.11") {
		for _, mapName := range []string{policyMap8Name, policyMap9Name, policyMap10Name} {
			policyMap, ok := spec.Maps[mapName]
			if !ok {
				return nil, fmt.Errorf("map %s not found in spec", mapName)
			}
			// Entries should be already set to 1 in the spec, but just in case
			policyMap.MaxEntries = 1
			if policyMap.InnerMap == nil {
				return nil, fmt.Errorf("map %s is not a hash of maps", mapName)
			}
			// this is the max key size supported on older kernels
			policyMap.InnerMap.KeySize = stringMapSize7
		}
	}

	// We just load the objects here so that we can pass the maps to other components but we don't load ebpf progs yet
	objs := bpfObjects{}
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: eBPFLogLevel,
		},
	}
	if err = spec.LoadAndAssign(&objs, opts); err != nil {
		return nil, fmt.Errorf("error loading objects: %w", err)
	}

	return &Manager{
		logger:              newLogger,
		objs:                &objs,
		enableLearning:      enableLearning,
		learningEventChan:   make(chan ProcessEvent, learningEventChanSize),
		monitoringEventChan: make(chan ProcessEvent, monitorEventChanSize),
		policyStringMaps: []*ebpf.Map{
			objs.PolStrMaps0,
			objs.PolStrMaps1,
			objs.PolStrMaps2,
			objs.PolStrMaps3,
			objs.PolStrMaps4,
			objs.PolStrMaps5,
			objs.PolStrMaps6,
			objs.PolStrMaps7,
			objs.PolStrMaps8,
			objs.PolStrMaps9,
			objs.PolStrMaps10,
		},
	}, nil
}

func (m *Manager) isKernelPre5_9() bool {
	m.kernelCheckOnce.Do(func() {
		m.isPre5_9 = kernels.CurrVersionIsLowerThan("5.9")
	})
	return m.isPre5_9
}

func (m *Manager) Start(ctx context.Context) error {
	defer func() {
		m.logger.InfoContext(ctx, "BPF Manager stopped")
		if err := m.objs.Close(); err != nil {
			m.logger.ErrorContext(ctx, "failed to close BPF objects", "error", err)
		}
	}()

	m.logger.InfoContext(ctx, "Starting BPF Manager...")
	g, ctx := errgroup.WithContext(ctx)

	// Cgroup Tracker
	g.Go(func() error {
		return m.cgroupTrackerStart(ctx)
	})

	// Learning
	if m.enableLearning {
		g.Go(func() error {
			return m.learningStart(ctx)
		})
	}

	// Monitoring
	g.Go(func() error {
		return m.monitoringStart(ctx)
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("BPF Manager error: %w", err)
	}
	return nil
}
