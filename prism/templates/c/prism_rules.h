#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <hs_runtime.h>

typedef struct prism_thread_state prism_thread_state_t;

bool prism_global_init(void);
void prism_global_fini(void);

bool prism_scratch_init(hs_scratch_t **scratch);

prism_thread_state_t *prism_thread_init(void);
void prism_thread_fini(prism_thread_state_t *st);
