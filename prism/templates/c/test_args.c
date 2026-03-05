#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include "prism_rules.h"
#include "prism_abi.h"

__attribute__((noreturn))
static void usage(int code)
{
	printf("Prism test program\n\n");
	printf("Usage:\n");
	printf("  Test the rules:\n");
// for hook in hook_defs
	printf("    --hook=/*{hook.name}*/\n");
// endfor
	printf("\n");
	printf("  Buffers:\n");
// for buf in buffers
	printf("    --/*{buf.arg_name}*/=STRING\n");
// endfor
	exit(code);
}

static struct sbuf parse_buf(const char *arg)
{
	return (struct sbuf){
		.len = strlen(arg),
		.ptr = arg,
	};
}

// for hook in hook_defs
static void setup_/*{hook.name}*/(const struct prism_all_buffers *in,
					union prism_entry_args *out)
{
// for buf_name in hook.buf_names
	out->/*{hook.name}*/./*{buf_name}*/ = in->/*{buf_name}*/;
// endfor
}
// endfor

struct hook_descr {
	const char *hook_name;
	enum prism_entry hook_entry;
	void (*hook_func)(const struct prism_all_buffers *in,
				union prism_entry_args *out);
};

static const struct hook_descr hook_defs[] = {
// for hook in hook_defs
	{
		.hook_name = "/*{hook.name}*/",
		.hook_entry = PRISM_ENTRY_/*{hook.name.upper()}*/,
		.hook_func = setup_/*{hook.name}*/,
	},
// endfor
};

static bool lookup_hook(const char *chosen_hook,
			const struct prism_all_buffers *bufs,
			struct prism_test_program_args *out)
{
	unsigned int i;

	for(i = 0; i < sizeof(hook_defs)/sizeof(hook_defs[0]); i++) {
		const struct hook_descr *d;

		d = &hook_defs[i];

		if (!strcmp(d->hook_name, chosen_hook)) {
			(*d->hook_func)(bufs, &out->entry_args);
			out->entry = d->hook_entry;
			return true;
		}
	}

	return false;
}

enum arg_index {
	HELP,
	HOOK,
// for buf in buffers
	BUF_/*{buf.name}*/,
// endfor
};

static const struct option long_opts[] = {
	{"help", no_argument, 0, 'h'},
	{"hook", required_argument, 0, 0},
// for buf in buffers
	{"/*{buf.arg_name}*/", required_argument, 0, 0},
// endfor
	{0, },
};

void prism_test_args_parse(int argc, char **argv,
				struct prism_test_program_args *out)
{
	struct prism_all_buffers bufs = {0, };
	const char *chosen_hook = NULL;
	bool hook_set = false;

	for(;;) {
		int c, opt;

		c = getopt_long(argc, argv, "h", long_opts, &opt);
		if (c < 0)
			break;

		switch(c) {
		case 0:
			switch (opt) {
// for buf in buffers
			case BUF_/*{buf.name}*/:
				bufs./*{buf.buf_name}*/ = parse_buf(optarg);
				break;
// endfor
			case HOOK:
				chosen_hook = optarg;
				break;
			case HELP:
			default:
				abort();
			}
			break;

		case 'h':
			usage(EXIT_SUCCESS);
			break;

		case '?':
		default:
			usage(EXIT_FAILURE);
			break;
		}
	}

	if (chosen_hook) {
		if (!lookup_hook(chosen_hook, &bufs, out)) {
			fprintf(stderr, "ERROR: "
				"unknown hook: %s\n", chosen_hook);
			usage(EXIT_FAILURE);
		}
		hook_set = true;
	}

	if (!hook_set) {
		fprintf(stderr, "ERROR: Missing argument: --hook\n");
		usage(EXIT_FAILURE);
	}
}
