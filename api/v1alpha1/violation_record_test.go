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

func (r ViolationRecord) withTimestamp(ts time.Time) ViolationRecord {
	r.Timestamp = metav1.NewTime(ts)
	return r
}

func TestViolationRecordKeyOf(t *testing.T) {
	baseTS := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	baseViolation := ViolationRecord{
		ID:             0,
		Timestamp:      baseTS,
		PodName:        "pod-a",
		ContainerName:  "c",
		ExecutablePath: "/x",
		NodeName:       "node-1",
		Action:         "monitor",
	}

	// If the timestamp changes the key should not change
	require.Equal(t,
		violationRecordKeyOf(baseViolation),
		violationRecordKeyOf(baseViolation.withTimestamp(baseTS.Add(time.Minute))))

	// different executable -> different keys
	require.NotEqual(t,
		violationRecordKeyOf(baseViolation.withExecutable("/x")),
		violationRecordKeyOf(baseViolation.withExecutable("/y")))

	// different pod name -> different keys
	require.NotEqual(t,
		violationRecordKeyOf(baseViolation.withPodName("pod-a")),
		violationRecordKeyOf(baseViolation.withPodName("pod-b")))

	// different container name -> different keys
	require.NotEqual(t,
		violationRecordKeyOf(baseViolation.withContainerName("c")),
		violationRecordKeyOf(baseViolation.withContainerName("d")))

	// different action -> different keys
	require.NotEqual(t,
		violationRecordKeyOf(baseViolation.withAction("monitor")),
		violationRecordKeyOf(baseViolation.withAction("protect")))
}

func TestMergeScrapedViolations(t *testing.T) {
	baseTS := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	baseViolation := ViolationRecord{
		ID:             0,
		Timestamp:      baseTS,
		PodName:        "pod-a",
		ContainerName:  "c",
		ExecutablePath: "/x",
		NodeName:       "node-1",
		Action:         "monitor",
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
				baseViolation.withExecutable("/y").withTimestamp(baseTS.Add(time.Minute)),
				baseViolation.withExecutable("/z").withTimestamp(baseTS.Add(time.Minute * 2)),
			},
			initialStatus: baseStatus,
			expectedStatus: WorkloadPolicyStatus{
				Violations: []ViolationRecord{
					baseViolation.withExecutable("/z").withID(2).withTimestamp(baseTS.Add(time.Minute * 2)),
					baseViolation.withExecutable("/y").withID(1).withTimestamp(baseTS.Add(time.Minute)),
					baseViolation.withExecutable("/x").withID(0),
				},
				ViolationCount: 3,
			},
		},
		{
			name: "scrape_new_and_old_violations",
			scraped: []ViolationRecord{
				// New timestamp but same violation
				baseViolation.withTimestamp(baseTS.Add(time.Hour)),
				baseViolation.withExecutable("/z").withTimestamp(baseTS.Add(time.Minute)),
			},
			initialStatus: baseStatus,
			expectedStatus: WorkloadPolicyStatus{
				Violations: []ViolationRecord{
					baseViolation.withExecutable("/x").withID(0).withTimestamp(baseTS.Add(time.Hour)),
					baseViolation.withExecutable("/z").withID(2).withTimestamp(baseTS.Add(time.Minute)),
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
					withTimestamp(baseTS.Add(time.Duration(101) * time.Minute)),
			},
			initialStatus: func() WorkloadPolicyStatus {
				r := make([]ViolationRecord, MaxViolationRecords)
				for i := range r {
					r[i] = baseViolation.withExecutable(fmt.Sprintf("/%d", i+1)).
						withID(int64(i)).
						withTimestamp(baseTS.Add(time.Duration(i+1) * time.Minute))
				}
				return WorkloadPolicyStatus{
					Violations:     r,
					ViolationCount: 100,
				}
			}(),
			expectedStatus: func() WorkloadPolicyStatus {
				r := make([]ViolationRecord, MaxViolationRecords+1)
				for i := range r {
					r[i] = baseViolation.withExecutable(fmt.Sprintf("/%d", i+1)).
						withID(int64(i)).
						withTimestamp(baseTS.Add(time.Duration(i+1) * time.Minute))
				}
				slices.SortStableFunc(r, func(a, b ViolationRecord) int {
					return b.Timestamp.Time.Compare(a.Timestamp.Time)
				})
				return WorkloadPolicyStatus{
					Violations:     r[:MaxViolationRecords],
					ViolationCount: 101,
				}
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.initialStatus.MergeScrapedViolations(tt.scraped)
			require.Equal(t, tt.expectedStatus, tt.initialStatus)
		})
	}
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
			wp.ClearAllowed()
			require.Equal(t, tt.expected, wp.Status.Violations)
		})
	}
}
