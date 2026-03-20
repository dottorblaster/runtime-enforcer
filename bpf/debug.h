#pragma once

#undef bpf_printk
#define bpf_printk(fmt, ...)                                                    \
	({                                                                          \
		if(load_time_config.debug_mode == 1) {                                  \
			static char ____fmt[] = fmt "\0";                                   \
			if(bpf_core_type_exists(struct trace_event_raw_bpf_trace_printk)) { \
				bpf_trace_printk(____fmt, sizeof(____fmt) - 1, ##__VA_ARGS__);  \
			} else {                                                            \
				____fmt[sizeof(____fmt) - 2] = '\n';                            \
				bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);      \
			}                                                                   \
		}                                                                       \
	})

// A single buffer shared between all CPUs
#define BUF_DIM (16 * 1024 * 1024)

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, BUF_DIM);
} ringbuf_logs SEC(".maps");

enum log_event_code {
	LOG_FAIL_TO_LOOKUP_EVT_MAP = 1,
	LOG_MISSING_FILE_STRUCT = 2,
	LOG_FAIL_TO_RESOLVE_PATH = 3,
	LOG_EMPTY_PATH = 4,
	LOG_FAIL_TO_COPY_EXEC_PATH = 5,
	LOG_DROP_EXEC_EVENT = 6,
	LOG_PATH_LEN_TOO_LONG = 7,
	LOG_POLICY_MODE_MISSING = 8,
	LOG_DROP_VIOLATION = 9,
	LOG_FAIL_TO_RESOLVE_CGROUP_ID = 10,
	LOG_FAIL_TO_RESOLVE_PARENT_CGROUP_ID = 11
} typedef log_code;

struct log_evt {
	log_code code;
	// args shared by all the logs
	char comm[TASK_COMM_LEN];
	u64 cg_tracker_id;
	u32 pid;
	u32 tgid;
	// additional args for specific log events
	u64 arg1;
	u64 arg2;
};

// Force emitting struct event into the ELF.
const struct log_evt *unused_log_evt __attribute__((unused));
const log_code *unused_log_event_code __attribute__((unused));
