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

// for db in hsdbs

extern const char /*{db.cvar_bin}*/[];
extern const size_t /*{db.cvar_size}*/;

// endfor

// for db in hsdbs
hs_database_t */*{db.cvar_db}*/;
// endfor

void prism_global_fini(void)
{
// for db in hsdbs
	hs_free_database(/*{db.cvar_db}*/);
// endfor
// for db in hsdbs
	/*{db.cvar_db}*/ = NULL;
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
	prism_thread_t *ret;

	ret = calloc(1, sizeof(*ret));
	if (ret == NULL) {
		fprintf(stderr,
			"prism_thread_init: calloc: %s",
			strerror(errno));
	}

	return ret;
}

prism_thread_t *prism_thread_new(void)
{
	prism_thread_t *ret;

	ret = alloc_thread();
	if (unlikely(ret == NULL))
		goto out;

	if (unlikely(!scratch_init(&ret->scratch)))
		goto out_free;

	goto out;

out_free:
	free(ret);
	ret = NULL;
out:
	return ret;
}

prism_thread_t *prism_thread_clone(const prism_thread_t *st)
{
	prism_thread_t *ret;
	hs_error_t rc;

	ret = alloc_thread();
	if (unlikely(ret == NULL))
		goto out;

	rc = hs_clone_scratch(st->scratch, &ret->scratch);
	if (rc != HS_SUCCESS)
		goto out_free;

out_free:
	free(ret);
	ret = NULL;
out:
	return ret;
}

void prism_thread_free(prism_thread_t *st)
{
	if (st) {
		hs_free_scratch(st->scratch);
		free(st);
	}
}
