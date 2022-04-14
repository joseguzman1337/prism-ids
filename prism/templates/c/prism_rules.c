#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <hs_runtime.h>

#include "prism_rules.h"
#include "prism_hs.h"
#include "prism_abi.h"
#include "prism_common.h"

static hs_database_t *hsdb_load(const char *name,
					const char *ptr,
					size_t len)
{
	hs_error_t hsret;
	hs_database_t *ret;

	hsret = hs_deserialize_database(ptr, len, &ret);
	if (hsret != HS_SUCCESS) {
		fprintf(stderr, "%s: hs_deserialize_database", name);
		return NULL;
	}

	return ret;
}

static inline pcre2_code *compile_regex(const char *regex, const int opts)
{
	pcre2_code *c;
	PCRE2_SIZE eo2;
	int en;

	c = pcre2_compile((PCRE2_SPTR8)regex,
				PCRE2_ZERO_TERMINATED,
				opts | PCRE2_NO_AUTO_CAPTURE,
				&en,
				&eo2,
				NULL);
	if (c == NULL && en == 115) {
		c = pcre2_compile((PCRE2_SPTR8)regex,
				PCRE2_ZERO_TERMINATED,
				opts,
				&en,
				&eo2,
				NULL);
	}
	if (c == NULL) {
		PCRE2_UCHAR err[256];

		pcre2_get_error_message(en, err, sizeof(err));
		fprintf(stderr, "/%s/ failed to compile at %d: %s\n",
			regex, (int)eo2, err);
		return NULL;
	}

	if (pcre2_jit_compile(c, PCRE2_JIT_COMPLETE)) {
		fprintf(stderr, "/%s/ failed to JIT\n", regex);
	}

	return c;
}

// for db in hsdbs

extern const char /*{db.cvar_bin}*/[];
extern const size_t /*{db.cvar_size}*/;

// endfor

// for db in hsdbs
hs_database_t */*{db.cvar_db}*/;
// endfor

// for pcre in pcres
pcre2_code */*{pcre.cvar_code}*/;
// endfor

void prism_global_fini(void)
{
// for db in hsdbs
	hs_free_database(/*{db.cvar_db}*/);
// endfor
// for pcre in pcres
	pcre2_code_free(/*{pcre.cvar_code}*/);
// endfor
// for db in hsdbs
	/*{db.cvar_db}*/ = NULL;
// endfor
// for pcre in pcres
	/*{pcre.cvar_code}*/ = NULL;
// endfor
}

bool prism_global_init(void)
{
// for db in hsdbs
	/*{db.cvar_db}*/ = hsdb_load("/*{db.name}*/",
		/*{db.cvar_bin}*/,
		/*{db.cvar_size}*/);
	if (/*{db.cvar_db}*/ == NULL)
		goto err;

// endfor
// for pcre in pcres
	/*{pcre.cvar_code}*/ = compile_regex(
		/*{pcre.regex|esc}*/,
		/*{pcre.opts}*/);
	if (/*{pcre.cvar_code}*/ == NULL)
		goto err;

// endfor

	return true;

err:
	prism_global_fini();
	return false;
}

static bool scratch_init(hs_scratch_t **scratch)
{
	size_t sz = 0;

// for db in hsdbs
	if (hs_alloc_scratch(/*{db.cvar_db}*/, scratch) != HS_SUCCESS) {
		fprintf(stderr, "%s: hs_alloc_scratch", "/*{db.name}*/");
		return false;
	}

// endfor
	hs_scratch_size(*scratch, &sz);
	fprintf(stderr, "prism: %zu bytes of scratch\n", sz);

	return true;
}

static prism_thread_t *alloc_thread(void)
{
	prism_thread_t *st;

	st = calloc(1, sizeof(*st));
	if (st == NULL) {
		fprintf(stderr,
			"prism_thread_init: calloc: %s",
			strerror(errno));
	}

	return st;
}

prism_thread_t *prism_thread_new(void)
{
	prism_thread_t *st;
	hs_error_t rc;

	st = alloc_thread();
	if (unlikely(st == NULL))
		goto out;

	if (unlikely(!scratch_init(&st->mpm_scratch)))
		goto out_free;

	rc = hs_clone_scratch(st->mpm_scratch, &st->scratch);
	if (rc != HS_SUCCESS)
		goto out_free_mpm;

// for pcre in pcres
	/* st->match = pcre2_match_data_create_from_pattern(c, NULL); */
// endfor

	goto out;

out_free_mpm:
	hs_free_scratch(st->mpm_scratch);
out_free:
	free(st);
	st = NULL;
out:
	return st;
}

prism_thread_t *prism_thread_clone(const prism_thread_t *orig)
{
	prism_thread_t *st;
	hs_error_t rc;

	st = alloc_thread();
	if (unlikely(st == NULL))
		goto out;

	rc = hs_clone_scratch(orig->mpm_scratch, &st->mpm_scratch);
	if (rc != HS_SUCCESS)
		goto out_free;

	rc = hs_clone_scratch(orig->scratch, &st->scratch);
	if (rc != HS_SUCCESS)
		goto out_free_mpm;

	goto out;

out_free_mpm:
	hs_free_scratch(st->mpm_scratch);
out_free:
	free(st);
	st = NULL;
out:
	return st;
}

void prism_thread_free(prism_thread_t *st)
{
	if (st) {
		hs_free_scratch(st->mpm_scratch);
		hs_free_scratch(st->scratch);
		free(st);
	}
}
