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
