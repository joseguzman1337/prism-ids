#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <hs_runtime.h>

bool prism_global_init(void);
void prism_global_fini(void);

typedef struct prism_thread_state prism_thread_t;

prism_thread_t *prism_thread_new(void);
prism_thread_t *prism_thread_clone(const prism_thread_t *st);
void prism_thread_free(prism_thread_t *st);
