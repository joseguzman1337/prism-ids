#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "prism_abi.h"
#include "blacklist.h"

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

#define STATE_BITMAP_SIZE /*{state_bitmap_sz}*/

struct prism_thread_state {
#if STATE_BITMAP_SIZE
	uint64_t state_bits[STATE_BITMAP_SIZE];
#endif
};

struct hs_shim {
	prism_thread_state_t *st;
	hs_scratch_t *scratch;
	size_t buf_len;
	const char *buf;
	struct prism_sidbuf *sidbuf;
};

#if STATE_BITMAP_SIZE
__attribute__((always_inline))
static inline bool state_bit_isset(const struct prism_thread_state *st,
					const unsigned int bit)
{
	return st->state_bits[bit >> 6] & (1UL << (bit & 0x3f));
}

__attribute__((always_inline))
static inline void state_bit_set(struct prism_thread_state *st,
					const unsigned int bit)
{
	st->state_bits[bit >> 6] |= (1UL << (bit & 0x3f));
}
#endif

static inline bool sidbuf_empty(const struct prism_sidbuf *buf)
{
	return buf->sid_cur == buf->sid_base;
}

static inline void sidbuf_reset(struct prism_sidbuf *buf)
{
	buf->sid_cur = (uint32_t *)buf->sid_base;
}

static inline void sidbuf_free(struct prism_sidbuf *buf)
{
	sidbuf_reset(buf);
	free(buf->sid_cur);
	buf->sid_cur = NULL;
	buf->sid_base = NULL;
}

static inline unsigned long sidbuf_nr_used(const struct prism_sidbuf *buf)
{
	return buf->sid_cur - buf->sid_base;
}

static inline bool sidbuf_alloc(struct prism_sidbuf *buf)
{
	const unsigned long max_rules = PRISM_SIDS_MAX + PRISM_BLACKLIST_SIDS;

	buf->sid_base = reallocarray(NULL, sizeof(*buf->sid_base), max_rules);
	if (buf->sid_base == NULL) {
		fprintf(stderr, "alloc sids: %s\n", strerror(errno));
		return false;
	}

	sidbuf_reset(buf);
	return true;
}

union tsc {
	struct {
		uint32_t eax;
		uint32_t edx;
	};
	uint64_t word;
};

__attribute__((always_inline))
static inline uint64_t rdtsc(void)
{
	union tsc ret;
	__builtin_ia32_mfence();
	asm volatile ("rdtsc" : "=a" (ret.eax), "=d" (ret.edx));
	return ret.word;
}
