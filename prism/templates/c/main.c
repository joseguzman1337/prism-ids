#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <math.h>

#include "prism_rules.h"
#include "prism_abi.h"
#include "blacklist.h"
#include "prism_common.h"


#if BENCHMARK
#define ITERS 1000000
#endif

void prism_match_sid(uint32_t sid, struct prism_sidbuf *buf)
{
#if BENCHMARK
	last_matched_sid = sid;
#endif
	*buf->sid_cur = sid;
	buf->sid_cur++;
}

static bool hook_thread(hs_scratch_t *scratch,
			prism_thread_state_t *st,
			enum prism_entry selected_entry,
			const union prism_entry_args *args)
{
	struct prism_sidbuf sidbuf;
#if BENCHMARK
	uint64_t begin, end;
	unsigned int i;
#endif
	bool ret = false;

	if (!sidbuf_alloc(&sidbuf))
		goto out;

#if BENCHMARK
	begin = rdtsc();
	for(i = 0; i < ITERS; i++) {
#endif
	switch (selected_entry) {
// for hook in hook_defs
	case PRISM_ENTRY_/*{hook.name.upper()}*/:
		entry_/*{hook.name}*/(
			st,
			scratch,
			&args->/*{hook.name}*/,
			&sidbuf);
		break;
// endfor
	default:
		abort();
	}
#if BENCHMARK
	}

	end = rdtsc();
	printf("%u iters in %lu cycles\n", ITERS, end - begin);
#endif

	ret = true;

	sidbuf_free(&sidbuf);
out:
	return ret;
}

static bool do_thread(const struct prism_test_program_args *args)
{
	hs_scratch_t *scratch = NULL;
	prism_thread_state_t *st;
	bool ret = false;

	if (!prism_scratch_init(&scratch)) {
		fprintf(stderr, "prism_scratch_init: failed\n");
		goto out;
	}

	st = prism_thread_init();
	if (st == NULL) {
		fprintf(stderr, "prism_thread_init: failed\n");
		goto out_free_scratch;
	}

	ret = hook_thread(scratch, st,
				args->entry,
				&args->entry_args);

	prism_thread_fini(st);
out_free_scratch:
	hs_free_scratch(scratch);
out:
	return ret;
}

int main(int argc, char **argv)
{
	static struct prism_test_program_args args;

	if (!prism_global_init()) {
		fprintf(stderr, "prism_global_init: failed\n");
		return EXIT_FAILURE;
	}

	prism_test_args_parse(argc, argv, &args);
	if (!do_thread(&args)) {
		return EXIT_FAILURE;
	}

	prism_global_fini();

	return EXIT_SUCCESS;
}
