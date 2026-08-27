package v1alpha1

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (r ViolationRecord) withID(id int64) ViolationRecord {
	r.ID = id
	return r
}

func (r ViolationRecord) withPodName(name string) ViolationRecord {
	r.PodName = name
	return r
}

func (r ViolationRecord) withNodeName(name string) ViolationRecord {
	r.NodeName = name
	return r
}

func (r ViolationRecord) withContainerName(name string) ViolationRecord {
	r.ContainerName = name
	return r
}

func (r ViolationRecord) withAction(action string) ViolationRecord {
	r.Action = action
	return r
}

func (r ViolationRecord) withExecutable(exec string) ViolationRecord {
	r.ExecutablePath = exec
	return r
}

func (r ViolationRecord) withLastObserved(ts time.Time) ViolationRecord {
	r.LastObservedTimestamp = metav1.NewTime(ts)
	return r
}

func (r ViolationRecord) withOccurrences(n int64) ViolationRecord {
	r.Occurrences = n
	return r
}

func (r ViolationRecord) withFirstObserved(ts time.Time) ViolationRecord {
	r.FirstObservedTimestamp = metav1.NewTime(ts)
	return r
}

func TestViolationRecordKeyOf(t *testing.T) {
	baseTS := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	baseViolation := ViolationRecord{
		ID:                    0,
		LastObservedTimestamp: baseTS,
		PodName:               "pod-a",
		ContainerName:         "c",
		ExecutablePath:        "/x",
		NodeName:              "node-1",
		Action:                "monitor",
	}

	// If the timestamp changes the key should not change
	require.Equal(t,
		baseViolation.key(),
		baseViolation.withLastObserved(baseTS.Add(time.Minute)).key())

	// different executable -> different keys
	require.NotEqual(t,
		baseViolation.withExecutable("/x").key(),
		baseViolation.withExecutable("/y").key())

	// different pod name -> different keys
	require.NotEqual(t,
		baseViolation.withPodName("pod-a").key(),
		baseViolation.withPodName("pod-b").key())

	// different container name -> different keys
	require.NotEqual(t,
		baseViolation.withContainerName("c").key(),
		baseViolation.withContainerName("d").key())

	// different action -> different keys
	require.NotEqual(t,
		baseViolation.withAction("monitor").key(),
		baseViolation.withAction("protect").key())
}

func TestMergeScrapedViolations(t *testing.T) {
	baseTS := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	baseViolation := ViolationRecord{
		ID:                     0,
		LastObservedTimestamp:  baseTS,
		Occurrences:            1,
		FirstObservedTimestamp: baseTS,
		PodName:                "pod-a",
		ContainerName:          "c",
		ExecutablePath:         "/x",
		NodeName:               "node-1",
		Action:                 "monitor",
	}

	baseStatus := WorkloadPolicyStatus{
		Violations:     []ViolationRecord{baseViolation},
		ViolationCount: 1,
	}

	tests := []struct {
		name           string
		scraped        []ViolationRecord
		initialStatus  WorkloadPolicyStatus
		expectedStatus WorkloadPolicyStatus
	}{
		{
			name:           "no_scraped_violations",
			scraped:        nil,
			initialStatus:  baseStatus,
			expectedStatus: baseStatus,
		},
		{
			name: "scrape_new_violations",
			scraped: []ViolationRecord{
				baseViolation.withExecutable("/y").withLastObserved(baseTS.Add(time.Minute)),
				baseViolation.withExecutable("/z").withLastObserved(baseTS.Add(time.Minute * 2)),
			},
			initialStatus: baseStatus,
			expectedStatus: WorkloadPolicyStatus{
				Violations: []ViolationRecord{
					baseViolation.withExecutable("/z").
						withID(2).
						withLastObserved(baseTS.Add(time.Minute * 2)).
						withFirstObserved(baseTS.Add(time.Minute * 2)),
					baseViolation.withExecutable("/y").
						withID(1).
						withLastObserved(baseTS.Add(time.Minute)).
						withFirstObserved(baseTS.Add(time.Minute)),
					baseViolation.withExecutable("/x").withID(0),
				},
				ViolationCount: 3,
			},
		},
		{
			name: "scrape_new_and_old_violations",
			scraped: []ViolationRecord{
				// New timestamp but same violation
				baseViolation.withLastObserved(baseTS.Add(time.Hour)),
				baseViolation.withExecutable("/z").withLastObserved(baseTS.Add(time.Minute)),
			},
			initialStatus: baseStatus,
			expectedStatus: WorkloadPolicyStatus{
				Violations: []ViolationRecord{
					baseViolation.withExecutable("/x").
						withID(0).
						withLastObserved(baseTS.Add(time.Hour)).
						withOccurrences(2),
					baseViolation.withExecutable("/z").
						withID(2).
						withLastObserved(baseTS.Add(time.Minute)).
						withFirstObserved(baseTS.Add(time.Minute)),
				},
				// Even if we have just 2 violations in the array, we have seen 3 of them.
				ViolationCount: 3,
			},
		},
		{
			name: "trim_to_MaxViolationRecords",
			scraped: []ViolationRecord{
				baseViolation.withExecutable("/101").
					withID(101).
					withLastObserved(baseTS.Add(time.Duration(101) * time.Minute)),
			},
			initialStatus: func() WorkloadPolicyStatus {
				r := make([]ViolationRecord, maxViolationRecords)
				for i := range r {
					r[i] = baseViolation.withExecutable(fmt.Sprintf("/%d", i+1)).
						withID(int64(i)).
						withLastObserved(baseTS.Add(time.Duration(i+1) * time.Minute)).
						withFirstObserved(baseTS.Add(time.Duration(i+1) * time.Minute)).
						withOccurrences(int64(i + 2))
				}
				return WorkloadPolicyStatus{
					Violations:     r,
					ViolationCount: 100,
				}
			}(),
			expectedStatus: func() WorkloadPolicyStatus {
				r := make([]ViolationRecord, maxViolationRecords+1)
				for i := range r {
					r[i] = baseViolation.withExecutable(fmt.Sprintf("/%d", i+1)).
						withID(int64(i)).
						withLastObserved(baseTS.Add(time.Duration(i+1) * time.Minute)).
						withFirstObserved(baseTS.Add(time.Duration(i+1) * time.Minute))
					if i < maxViolationRecords {
						r[i] = r[i].withOccurrences(int64(i + 2))
					}
				}
				slices.SortStableFunc(r, func(a, b ViolationRecord) int {
					return b.LastObservedTimestamp.Time.Compare(a.LastObservedTimestamp.Time)
				})
				return WorkloadPolicyStatus{
					Violations:     r[:maxViolationRecords],
					ViolationCount: 101,
				}
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.initialStatus.mergeScrapedViolations(tt.scraped)
			require.Equal(t, tt.expectedStatus, tt.initialStatus)
		})
	}
}

func TestMergeScrapedViolationsMultiBatch(t *testing.T) {
	baseTS := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	baseViolation := ViolationRecord{
		LastObservedTimestamp: baseTS,
		PodName:               "pod-a",
		ContainerName:         "c",
		ExecutablePath:        "/x",
		NodeName:              "node-1",
		Action:                "monitor",
	}

	status := WorkloadPolicyStatus{}

	// Batch 1: /x and /y are observed for the first time.
	status.mergeScrapedViolations([]ViolationRecord{
		baseViolation.withExecutable("/x").withLastObserved(baseTS.Time),
		baseViolation.withExecutable("/y").withLastObserved(baseTS.Time),
	})

	require.Len(t, status.Violations, 2)
	require.Equal(t, int64(2), status.ViolationCount)

	// Batch 2: /x once more, /y twice in the same batch, and a new /z.
	status.mergeScrapedViolations([]ViolationRecord{
		baseViolation.withExecutable("/x").withLastObserved(baseTS.Add(time.Minute)),
		baseViolation.withExecutable("/y").withLastObserved(baseTS.Add(time.Minute)),
		baseViolation.withExecutable("/y").withLastObserved(baseTS.Add(time.Minute * 2)),
		baseViolation.withExecutable("/z").withLastObserved(baseTS.Add(time.Minute)),
	})

	require.Len(t, status.Violations, 3)
	require.Equal(t, int64(6), status.ViolationCount)

	findByExe := func(exe string) ViolationRecord {
		idx := slices.IndexFunc(status.Violations, func(v ViolationRecord) bool {
			return v.ExecutablePath == exe
		})
		require.NotEqual(t, -1, idx, "violation %s not found", exe)
		return status.Violations[idx]
	}

	// Per-record counts accumulate across batches (including duplicates
	// within a single batch), and firstObservedTimestamp is stamped with
	// the first sighting and never updated, while lastObservedTimestamp
	// tracks the newest occurrence.
	x := findByExe("/x")
	require.Equal(t, int64(2), x.Occurrences)
	require.Equal(t, baseTS, x.FirstObservedTimestamp)
	require.Equal(t, baseTS.Add(time.Minute), x.LastObservedTimestamp.Time)

	y := findByExe("/y")
	require.Equal(t, int64(3), y.Occurrences)
	require.Equal(t, baseTS, y.FirstObservedTimestamp)
	require.Equal(t, baseTS.Add(time.Minute*2), y.LastObservedTimestamp.Time)

	z := findByExe("/z")
	require.Equal(t, int64(1), z.Occurrences)
	require.Equal(t, baseTS.Add(time.Minute), z.FirstObservedTimestamp.Time)
	require.Equal(t, baseTS.Add(time.Minute), z.LastObservedTimestamp.Time)
}

func TestClearAllowedViolations(t *testing.T) {
	createViolationRecord := func(container, exe string) ViolationRecord {
		return ViolationRecord{
			ContainerName:  container,
			ExecutablePath: exe,
		}
	}

	tests := []struct {
		name       string
		violations []ViolationRecord
		rules      map[string]*WorkloadPolicyRules
		expected   []ViolationRecord
	}{
		{
			name: "drops violations for allowed executable/container pairs",
			violations: []ViolationRecord{
				createViolationRecord("app", "/usr/bin/app"),
				createViolationRecord("app", "/usr/bin/other"),
				createViolationRecord("sidecar", "/usr/bin/app"),
			},
			rules: map[string]*WorkloadPolicyRules{
				"app": {
					Executables: WorkloadPolicyExecutables{
						Allowed: []string{"/usr/bin/app", "/bin/sh"},
					},
				},
			},
			expected: []ViolationRecord{
				createViolationRecord("app", "/usr/bin/other"),
				createViolationRecord("sidecar", "/usr/bin/app"),
			},
		},
		{
			name:       "nil rules leave violations untouched",
			violations: []ViolationRecord{createViolationRecord("app", "/usr/bin/app")},
			rules:      nil,
			expected:   []ViolationRecord{createViolationRecord("app", "/usr/bin/app")},
		},
		{
			name:       "empty rules leave violations untouched",
			violations: []ViolationRecord{createViolationRecord("app", "/usr/bin/app")},
			rules:      map[string]*WorkloadPolicyRules{},
			expected:   []ViolationRecord{createViolationRecord("app", "/usr/bin/app")},
		},
		{
			name:       "container with nil rules does not panic",
			violations: []ViolationRecord{createViolationRecord("app", "/usr/bin/app")},
			rules:      map[string]*WorkloadPolicyRules{"app": nil},
			expected:   []ViolationRecord{createViolationRecord("app", "/usr/bin/app")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wp := &WorkloadPolicy{
				Spec:   WorkloadPolicySpec{RulesByContainer: tt.rules},
				Status: WorkloadPolicyStatus{Violations: tt.violations},
			}
			wp.clearAllowedViolations()
			require.Equal(t, tt.expected, wp.Status.Violations)
		})
	}
}

func TestAcknowledgeViolationsFromAnnotations(t *testing.T) {
	now := metav1.NewTime(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))

	newViolation := func(id int64) ViolationRecord {
		return ViolationRecord{
			ID:                    id,
			LastObservedTimestamp: metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			PodName:               fmt.Sprintf("pod-%d", id),
			ContainerName:         fmt.Sprintf("container-%d", id),
			ExecutablePath:        fmt.Sprintf("/usr/bin/exe-%d", id),
			NodeName:              fmt.Sprintf("node-%d", id),
			Action:                "monitor",
		}
	}

	newAck := func(id int64, reason string, at metav1.Time) AcknowledgedViolationRecord {
		return AcknowledgedViolationRecord{
			Violation: newViolation(id), Reason: reason, AcknowledgedAt: at}
	}

	tests := []struct {
		name             string
		annotations      map[string]string
		violations       []ViolationRecord
		acknowledged     []AcknowledgedViolationRecord
		wantAnnotations  map[string]string
		wantViolations   []ViolationRecord
		wantAcknowledged []AcknowledgedViolationRecord
		wantReturned     []AcknowledgedViolationRecord
	}{
		{
			name:            "unrelated_annotations",
			annotations:     map[string]string{"unrelated.io/key": "value"},
			violations:      []ViolationRecord{newViolation(1)},
			wantAnnotations: map[string]string{"unrelated.io/key": "value"},
			wantViolations:  []ViolationRecord{newViolation(1)},
		},
		{
			name: "multiple_annotations_match_multiple_violations",
			annotations: map[string]string{
				ViolationAcknowledgePrefix + "1": "reason one",
				ViolationAcknowledgePrefix + "2": "reason two",
			},
			violations: []ViolationRecord{
				newViolation(1),
				newViolation(2),
			},
			wantAnnotations: map[string]string{},
			wantViolations:  []ViolationRecord{},
			wantAcknowledged: []AcknowledgedViolationRecord{
				newAck(1, "reason one", now),
				newAck(2, "reason two", now),
			},
			wantReturned: []AcknowledgedViolationRecord{
				newAck(1, "reason one", now),
				newAck(2, "reason two", now),
			},
		},
		{
			name: "partial_match_leaves_unacknowledged_violation",
			annotations: map[string]string{
				ViolationAcknowledgePrefix + "1": "acknowledged",
				// we will leave both annotations untouched
				ViolationAcknowledgePrefix + "999":    "no match",
				ViolationAcknowledgePrefix + "random": "wrong key",
			},
			violations: []ViolationRecord{newViolation(1)},
			// This policy already has an acknowledged violation, that should remain untouched
			acknowledged: []AcknowledgedViolationRecord{newAck(2, "acknowledged", now)},
			wantAnnotations: map[string]string{
				ViolationAcknowledgePrefix + "999":    "no match",
				ViolationAcknowledgePrefix + "random": "wrong key",
			},
			wantViolations: []ViolationRecord{},
			wantAcknowledged: []AcknowledgedViolationRecord{
				newAck(2, "acknowledged", now),
				newAck(1, "acknowledged", now),
			},
			wantReturned: []AcknowledgedViolationRecord{
				newAck(1, "acknowledged", now),
			},
		},
		{
			name: "acknowledge_with_empty_violations",
			annotations: map[string]string{
				ViolationAcknowledgePrefix + "1": "reason",
			},
			wantAnnotations: map[string]string{ViolationAcknowledgePrefix + "1": "reason"},
		},
		{
			name: "trims_acknowledged_violations_to_MaxViolationRecords",
			annotations: map[string]string{
				ViolationAcknowledgePrefix + "101": "acknowledged",
			},
			violations: []ViolationRecord{newViolation(101)},
			// This policy already has an acknowledged violation, that should remain untouched
			acknowledged: func() []AcknowledgedViolationRecord {
				r := make([]AcknowledgedViolationRecord, maxViolationRecords)
				for i := range r {
					r[i] = newAck(int64(i), "acknowledged", now)
				}
				return r
			}(),
			wantAnnotations: map[string]string{},
			wantViolations:  []ViolationRecord{},
			wantAcknowledged: func() []AcknowledgedViolationRecord {
				r := make([]AcknowledgedViolationRecord, maxViolationRecords+1)
				for i := range r {
					r[i] = newAck(int64(i), "acknowledged", now)
				}
				r[maxViolationRecords] = newAck(101, "acknowledged", now)
				slices.SortFunc(r, func(a, b AcknowledgedViolationRecord) int {
					return b.AcknowledgedAt.Time.Compare(a.AcknowledgedAt.Time)
				})
				return r[:maxViolationRecords]
			}(),
			wantReturned: []AcknowledgedViolationRecord{
				newAck(101, "acknowledged", now),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wp := &WorkloadPolicy{
				Annotations: tt.annotations,
				Status: WorkloadPolicyStatus{
					Violations:             tt.violations,
					AcknowledgedViolations: tt.acknowledged,
				},
			}

			returned := wp.acknowledgeViolationsFromAnnotations(now)

			require.Equal(t, tt.wantAnnotations, wp.GetAnnotations())
			require.ElementsMatch(t, tt.wantViolations, wp.Status.Violations)
			require.ElementsMatch(t, tt.wantAcknowledged, wp.Status.AcknowledgedViolations)
			require.ElementsMatch(t, tt.wantReturned, returned)
		})
	}
}
