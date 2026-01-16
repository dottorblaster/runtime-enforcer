package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/neuvector/runtime-enforcer/internal/types/policymode"
)

type mode int

const (
	learning mode = iota
	monitoring
)

func (mod mode) String() string {
	switch mod {
	case learning:
		return "learning"
	case monitoring:
		return "monitoring"
	default:
		return "unknown"
	}
}

func (m *Manager) setupEventConsumer(ctx context.Context, mod mode) error {
	var progLink link.Link
	defer func() {
		m.logger.InfoContext(ctx, "stopped consumer", "mode", mod.String())
		if progLink != nil {
			if err := progLink.Close(); err != nil {
				m.logger.ErrorContext(ctx, "closing program link", "error", err, "mode", mod.String())
			}
		}
	}()

	var err error

	prog := m.objs.ExecveSend
	outChan := m.learningEventChan
	buf := m.objs.RingbufExecve
	if mod == monitoring {
		prog = m.objs.EnforceCgroupPolicy
		outChan = m.monitoringEventChan
		buf = m.objs.RingbufMonitoring
	}

	progLink, err = link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		return fmt.Errorf("failed to attach %s prog: %w", prog.String(), err)
	}

	rd, err := ringbuf.NewReader(buf)
	if err != nil {
		return fmt.Errorf("opening %s ringbuf reader: %w", buf.String(), err)
	}

	return m.processRingbufEvents(ctx, rd, outChan)
}

// processRingbufEvents is a small helper used by both learning and monitoring loops.
// It reads events from the given ring buffer and sends them to the provided channel.
func (m *Manager) processRingbufEvents(ctx context.Context, rd *ringbuf.Reader, out chan<- ProcessEvent) error {
	// Goroutine to close the reader when context is done.
	go func() {
		<-ctx.Done()
		if err := rd.Close(); err != nil {
			m.logger.ErrorContext(ctx, "closing ringbuf reader", "error", err)
		}
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				m.logger.InfoContext(ctx, "ringbuf reader closed")
				return nil
			}
			return fmt.Errorf("reading from reader: %w", err)
		}

		buf := bytes.NewBuffer(record.RawSample)
		var header bpfEventHeader
		if err = binary.Read(buf, binary.LittleEndian, &header); err != nil {
			m.logger.ErrorContext(ctx, "parsing ringbuf event", "error", err)
			continue
		}

		// 4096 is the maximum supported path size in the eBPF program.
		const maxPathLen = 4096
		if header.PathLen > maxPathLen {
			m.logger.ErrorContext(ctx, "invalid path length in ringbuf event", "length", header.PathLen)
			continue
		}

		// header.PathLen doesn't include the string terminator `\0`.
		pathBytes := make([]byte, header.PathLen)
		if _, err = buf.Read(pathBytes); err != nil {
			m.logger.ErrorContext(ctx, "reading path bytes", "error", err)
			continue
		}

		modeString := ""
		// 0 is the value we receive in learning mode, meaning "not set".
		if header.Mode != 0 {
			modeString = policymode.FromUint8(header.Mode).String()
		}
		out <- ProcessEvent{
			CgroupID:    header.Cgid,
			CgTrackerID: header.CgTrackerID,
			Mode:        modeString,
			ExePath:     string(pathBytes),
		}
	}
}
