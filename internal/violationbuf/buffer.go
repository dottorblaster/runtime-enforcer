package violationbuf

import (
	"sync"
	"time"
)

// dedupKey identifies a unique violation for deduplication purposes.
type dedupKey struct {
	PolicyName    string
	PodName       string
	ContainerName string
	ExePath       string
	Action        string
}

// ViolationInfo contains the details of a single policy violation event.
type ViolationInfo struct {
	PolicyName    string
	Namespace     string
	PodName       string
	ContainerName string
	ExePath       string
	NodeName      string
	Action        string
}

// ViolationRecord is a deduplicated violation record ready for scraping.
type ViolationRecord struct {
	Timestamp     time.Time
	PolicyName    string
	Namespace     string
	PodName       string
	ContainerName string
	ExePath       string
	NodeName      string
	Action        string
	Count         uint32
}

// MaxBufferEntries is the maximum number of unique violation keys the buffer
// will hold between drains. Once the limit is reached, new unique violations
// are dropped (existing keys still get their count incremented). This prevents
// unbounded memory growth when the controller is slow to scrape.
const MaxBufferEntries = 10_000

// Buffer is a thread-safe in-memory violation buffer with deduplication.
// The EventScraper calls Record() for each violation; the gRPC server calls
// Drain() when the controller scrapes.
type Buffer struct {
	mtx     sync.Mutex
	entries map[dedupKey]*ViolationRecord
	dropped uint64
}

// NewBuffer creates a new violation buffer.
func NewBuffer() *Buffer {
	return &Buffer{
		entries: make(map[dedupKey]*ViolationRecord),
	}
}

// Record upserts a violation into the buffer. If a record with the same
// dedup key already exists, the count is incremented and the timestamp
// is updated.
func (b *Buffer) Record(info ViolationInfo) {
	key := dedupKey{
		PolicyName:    info.PolicyName,
		PodName:       info.PodName,
		ContainerName: info.ContainerName,
		ExePath:       info.ExePath,
		Action:        info.Action,
	}

	b.mtx.Lock()
	defer b.mtx.Unlock()

	if rec, ok := b.entries[key]; ok {
		rec.Count++
		rec.Timestamp = time.Now()
		return
	}

	if len(b.entries) >= MaxBufferEntries {
		b.dropped++
		return
	}

	b.entries[key] = &ViolationRecord{
		Timestamp:     time.Now(),
		PolicyName:    info.PolicyName,
		Namespace:     info.Namespace,
		PodName:       info.PodName,
		ContainerName: info.ContainerName,
		ExePath:       info.ExePath,
		NodeName:      info.NodeName,
		Action:        info.Action,
		Count:         1,
	}
}

// Drain atomically swaps the buffer, returning all accumulated records
// and leaving an empty buffer. The dropped counter is also reset.
func (b *Buffer) Drain() []ViolationRecord {
	b.mtx.Lock()
	old := b.entries
	b.entries = make(map[dedupKey]*ViolationRecord)
	b.dropped = 0
	b.mtx.Unlock()

	records := make([]ViolationRecord, 0, len(old))
	for _, rec := range old {
		records = append(records, *rec)
	}
	return records
}

// Dropped returns the number of unique violations dropped since the last drain
// because the buffer was at capacity.
func (b *Buffer) Dropped() uint64 {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return b.dropped
}
