package violationbuf

import (
	"sync"
	"time"
)

// ViolationRecord is a violation record ready for scraping.
type ViolationRecord struct {
	Timestamp     time.Time
	PolicyName    string
	Namespace     string
	PodName       string
	ContainerName string
	ExePath       string
	NodeName      string
	Action        string
	WorkloadName  string
	WorkloadKind  string
}

// MaxBufferEntries is the capacity of the ring buffer. When full, the oldest
// entry is overwritten.
const MaxBufferEntries = 10_000

// Buffer is a thread-safe ring buffer for violation records.
// The EventScraper calls Record() for each violation; the gRPC server calls
// Drain() when the controller scrapes.
type Buffer struct {
	mtx sync.Mutex
	buf []ViolationRecord
	pos int64
}

// NewBuffer creates a new violation buffer.
func NewBuffer() *Buffer {
	return &Buffer{
		buf: make([]ViolationRecord, MaxBufferEntries),
	}
}

// Record appends a violation to the ring buffer. If the buffer is full,
// the oldest entry is overwritten and dropped is returned as true.
func (b *Buffer) Record(rec ViolationRecord) bool {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	dropped := b.pos >= MaxBufferEntries

	b.buf[b.pos%MaxBufferEntries] = rec
	b.pos++

	return dropped
}

// Drain returns all buffered records in reverse chronological order (newest first)
// and resets the buffer.
func (b *Buffer) Drain() []ViolationRecord {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	n := min(b.pos, MaxBufferEntries)
	if n == 0 {
		return nil
	}

	records := make([]ViolationRecord, 0, n)
	for i := range n {
		idx := (b.pos - 1 - i) % MaxBufferEntries
		records = append(records, b.buf[idx])
	}

	b.pos = 0

	return records
}
