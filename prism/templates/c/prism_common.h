#pragma once

#define PRISM_RULE_TRACE 0
#if PRISM_RULE_TRACE
#define trace(...) fprintf(stderr, __VA_ARGS__)
#else
#define trace(...) do { } while (0)
#endif

#ifndef likely
#define likely(x) __builtin_expect((bool)(x), true)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect((bool)(x), false)
#endif

struct prism_thread_state {
	hs_scratch_t *mpm_scratch;
	hs_scratch_t *scratch;
};

struct hs_shim {
	struct prism_thread_state *st;
	const void *bufs;
	struct prism_sidbuf *sidbuf;
};
