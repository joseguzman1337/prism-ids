#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <cpuid.h>

/* All this code ripped from DPDK and lightly modified */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

static uint64_t rdmsr(int msr)
{
	uint64_t val;
	ssize_t ret;
	int fd;

	fd = open("/dev/cpu/0/msr", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "/dev/cpu/0/msr: open: %s\n", strerror(errno));
		abort();
	}

	ret = pread(fd, &val, sizeof(val), msr);
	if (ret < (int)sizeof(val))
		abort();

	close(fd);

	return val;
}

static unsigned int cpu_get_model(uint32_t fam_mod_step)
{
	uint32_t family, model, ext_model;

	family = (fam_mod_step >> 8) & 0xf;
	model = (fam_mod_step >> 4) & 0xf;

	if (family == 6 || family == 15) {
		ext_model = (fam_mod_step >> 16) & 0xf;
		model += (ext_model << 4);
	}

	return model;
}

static bool check_model_wsm_nhm(uint8_t model)
{
	switch (model) {
	/* Westmere */
	case 0x25:
	case 0x2C:
	case 0x2F:
	/* Nehalem */
	case 0x1E:
	case 0x1F:
	case 0x1A:
	case 0x2E:
		return true;
	default:
		return false;
	}

}

static bool check_model_gdm_dnv(uint8_t model)
{
	switch (model) {
	/* Goldmont */
	case 0x5C:
	/* Denverton */
	case 0x5F:
		return true;
	default:
		return false;
	}
}

static uint64_t get_tsc_freq(void)
{
	uint64_t tsc_hz = 0;
	uint32_t a, b, c, d, maxleaf;
	uint8_t mult, model;

	/*
	 * Time Stamp Counter and Nominal Core Crystal Clock
	 * Information Leaf
	 */
	maxleaf = __get_cpuid_max(0, NULL);

	if (maxleaf >= 0x15) {
		__cpuid(0x15, a, b, c, d);

		/* EBX : TSC/Crystal ratio, ECX : Crystal Hz */
		if (b && c) {
			printf("from cpuid\n");
			return c * (b / a);
		}
	}

	__cpuid(0x1, a, b, c, d);
	model = cpu_get_model(a);

	if (check_model_wsm_nhm(model))
		mult = 133;
	else if ((c & bit_AVX) || check_model_gdm_dnv(model))
		mult = 100;
	else
		abort();

	tsc_hz = rdmsr(0xCE);

	printf("from msr (ratio=%lu mult=%u)\n",
		(tsc_hz >> 8) & 0xff, mult);
	return ((tsc_hz >> 8) & 0xff) * mult * 1E6;
}

static inline uint64_t rdtsc(void)
{
	union {
		uint64_t tsc_64;
		struct {
			uint32_t lo_32;
			uint32_t hi_32;
		};
	} tsc;

#if VMWARE_TSC_MAP
	/* ecx = 0x10000 corresponds to the physical TSC for VMware */
	asm volatile("rdpmc" :
		     "=a" (tsc.lo_32),
		     "=d" (tsc.hi_32) :
		     "c"(0x10000));
#else
	asm volatile("rdtsc" :
		     "=a" (tsc.lo_32),
		     "=d" (tsc.hi_32));
#endif
	return tsc.tsc_64;
}

static inline uint64_t rdtsc_fence(void)
{
	__builtin_ia32_mfence();
	return rdtsc();
}

int main(int argc, char **argv)
{
	printf("%lu Hz rdtsc freq.\n", get_tsc_freq());
	return 0;
}
