#pragma once

struct prism_sidbuf {
	uint32_t *sid_cur;
	const uint32_t *sid_base;
};

struct sbuf {
	size_t len;
	const char *ptr;
};

// for hook in hook_defs

struct /*{hook.name}*/_buffers {
// for buf_name in hook.buf_names
	struct sbuf /*{buf_name}*/;
// endfor
};

// endfor

/* Rule matching entry points */
// for hook in hook_defs
void entry_/*{hook.name}*/(prism_thread_t *st,
				const struct /*{hook.name}*/_buffers *bufs,
				struct prism_sidbuf *sidbuf);
// endfor

// for hook, nr_sids in nr_sids.items()
#define PRISM_SIDS_/*{hook.name.upper()}*/ /*{nr_sids}*/
// endfor

#define PRISM_SIDS_MAX /*{nr_sids.values()|max}*/

union prism_entry_args {
// for hook in hook_defs
	struct /*{hook.name}*/_buffers /*{hook.name}*/;
// endfor
};

enum prism_entry {
	// for hook in hook_defs
	PRISM_ENTRY_/*{hook.name.upper()}*/,
	// endfor
};

struct prism_all_buffers {
// for buf_name in all_buffers
	struct sbuf /*{buf_name}*/;
// endfor
};

/* For the test program */
struct prism_test_program_args {
	union prism_entry_args entry_args;
	enum prism_entry entry;
};

void prism_test_args_parse(int argc, char **argv,
				struct prism_test_program_args *args);

/* Functions exported to prism */
void prism_match_sid(uint32_t sid, struct prism_sidbuf *buf);
