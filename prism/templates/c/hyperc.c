#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>

#include <hs_compile.h>

#define ERR(fmt, x...) fprintf(stderr, "ERROR: %s:%u: " fmt "\n", \
				__func__, __LINE__, ##x)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#endif

#if __GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 96)
# ifndef likely
#  define likely(x) __builtin_expect(!!(x), 1)
# endif
# ifndef unlikely
#  define unlikely(x) __builtin_expect(!!(x), 0)
# endif
#else
# define likely(x) (x)
# define unlikely(x) (x)
#endif

struct params {
	unsigned int mode;
	hs_platform_info_t arch;
	const char *in_file;
	const char *out_file;
};

struct pat_desc {
	unsigned int id;
	unsigned int flags;
	hs_expr_ext_t ext;
	char *regexp;
};

struct hspats {
	const char **exprs;
	unsigned int *flags;
	unsigned int *ids;
	const hs_expr_ext_t **extp;
	hs_expr_ext_t *ext;
};

struct pat_file {
	unsigned int nr_pats;
	struct pat_desc *pat;
};

static hs_database_t *compile_patterns(const struct pat_file *pf,
					const unsigned int mode,
					const hs_platform_info_t * const arch)
{
	unsigned int i;
	struct hspats hsp = {0, };
	hs_error_t hsret;
	hs_compile_error_t *cerr = NULL;
	hs_database_t *hsdb = NULL;

	hsp.exprs = reallocarray(NULL, pf->nr_pats, sizeof(*hsp.exprs));
	hsp.flags = reallocarray(NULL, pf->nr_pats, sizeof(*hsp.flags));
	hsp.ids = reallocarray(NULL, pf->nr_pats, sizeof(*hsp.ids));
	hsp.extp = reallocarray(NULL, pf->nr_pats, sizeof(*hsp.extp));
	hsp.ext = reallocarray(NULL, pf->nr_pats, sizeof(*hsp.ext));

	if (hsp.exprs == NULL
			|| hsp.flags == NULL
			|| hsp.ids == NULL
			|| hsp.extp == NULL
			|| hsp.ext == NULL) {
		ERR("malloc: %s", strerror(errno));
		goto out_free;
	}

	for (i = 0; i < pf->nr_pats; i++) {
		hsp.exprs[i] = pf->pat[i].regexp;
		hsp.flags[i] = pf->pat[i].flags;
		hsp.extp[i] = &hsp.ext[i];
		hsp.ids[i] = pf->pat[i].id;
		hsp.ext[i] = pf->pat[i].ext;
	}

	hsret = hs_compile_ext_multi(hsp.exprs,
					hsp.flags,
					hsp.ids,
					hsp.extp,
					pf->nr_pats,
					mode,
					arch,
					&hsdb,
					&cerr);
	if (hsret != HS_SUCCESS) {
		ERR("hs_compile_ext_multi: %s", cerr->message);
		if (cerr->expression >= 0) {
			ERR("bad expression: %s", hsp.exprs[cerr->expression]);
		}
		hsdb = NULL;
		goto out_free;
	}

out_free:
	free(hsp.exprs);
	free(hsp.flags);
	free(hsp.ids);
	free(hsp.extp);
	free(hsp.ext);
	return hsdb;
}

static struct pat_file *pat_file(void)
{
	struct pat_file *ret;

	ret = calloc(1, sizeof(*ret));
	if (ret == NULL)
		abort();

	return ret;
}

static bool pat_file_add_pat(struct pat_file * const pf,
				const struct pat_desc desc)
{
	if ((pf->nr_pats & 0xf) == 0) {
		const unsigned int new_max = pf->nr_pats + 0x10;
		void *new;

		new = reallocarray(pf->pat, new_max, sizeof(*pf->pat));
		//new = realloc(pf->pat, new_max * sizeof(*pf->pat));
		if (new == NULL) {
			return false;
		}

		pf->pat = new;
	}

	pf->pat[pf->nr_pats++] = (struct pat_desc) {
		.id = desc.id,
		.ext = desc.ext,
		.regexp = strdup(desc.regexp),
	};

	return true;
}

static void pat_file_free(struct pat_file *pf)
{
	unsigned int i;

	if (pf) {
		for (i = 0; i < pf->nr_pats; i++) {
			free(pf->pat[i].regexp);
		}
		free(pf->pat);
		free(pf);
	}
}

static bool set_ext(const char * const key,
			const char * const val,
			hs_expr_ext_t out[static const 1])
{
	unsigned long parsed;
	char *end;

	errno = 0;
	parsed = strtoul(val, &end, 10);
	if (errno || *end != '\0') {
		ERR("Unable to parse %s of \"%s\"", key, val);
		return false;
	}

	if (!strcmp(key, "min_offset")) {
		out->flags = HS_EXT_FLAG_MIN_OFFSET;
		out->min_offset = parsed;
	} else if (!strcmp(key, "max_offset")) {
		out->flags = HS_EXT_FLAG_MAX_OFFSET;
		out->max_offset = parsed;
	} else if (!strcmp(key, "min_length")) {
		out->flags = HS_EXT_FLAG_MIN_LENGTH;
		out->min_length = parsed;
	} else if (!strcmp(key, "edit_distance")) {
		out->flags = HS_EXT_FLAG_EDIT_DISTANCE;
		out->edit_distance = parsed;
	} else if (!strcmp(key, "hamming_distance")) {
		out->flags = HS_EXT_FLAG_HAMMING_DISTANCE;
		out->hamming_distance = parsed;
	} else {
		ERR("Unknown extended flag: \"%s\"", key);
		return false;
	}

	return true;
}

static bool parse_ext(char *ptr, hs_expr_ext_t ext[static const 1])
{
	unsigned int i, n;
	char *tok[8]; /* there are only 5 possible... */

	for (n = 0; n < ARRAY_SIZE(tok); n++) {
		tok[n] = strtok(ptr, ",");
		if (tok[n] == NULL)
			break;
		ptr = NULL;
	}

	for (i = 0; tok[i] != NULL; i++) {
		const char * const key = strtok(tok[i], "=");

		if (key == NULL) {
			ERR("Unable to parse extended flag: %s", tok[i]);
		}

		const char * const val = strtok(NULL, "=");

		if (val == NULL) {
			ERR("Unable to parse extended flag");
			return false;
		}

		if (!set_ext(key, val, ext)) {
			return false;
		}
	}

	return true;
}

static bool parse_ext_token(char *ptr,
				hs_expr_ext_t ext[static const 1])
{
	char * const end = strrchr(ptr, '}');

	if (end == NULL) {
		ERR("No closing brace for extended flag");
		return false;
	}

	*end = '\0';

	/* XXX: should check for trailing garbage? */

	return parse_ext(ptr, ext);
}

static bool parse_flags_ext(char *ptr,
				unsigned int * const out_flags,
				hs_expr_ext_t *out_ext)
{
	hs_expr_ext_t ext = {0, };
	unsigned int flags = 0;
	bool ret;

	while (true) {
		const char cur = *(ptr++);

		switch (cur) {
		case 'i':
			flags |= HS_FLAG_CASELESS;
			break;
		case 's':
			flags |= HS_FLAG_DOTALL;
			break;
		case 'm':
			flags |= HS_FLAG_MULTILINE;
			break;
		case 'H':
			flags |= HS_FLAG_SINGLEMATCH;
			break;
		case 'V':
			flags |= HS_FLAG_ALLOWEMPTY;
			break;
		case '8':
			flags |= HS_FLAG_UTF8;
			break;
		case 'W':
			flags |= HS_FLAG_UCP;
			break;
		case 'P':
			flags |= HS_FLAG_PREFILTER;
			break;
		case 'L':
			flags |= HS_FLAG_SOM_LEFTMOST;
			break;
		case 'C':
			flags |= HS_FLAG_COMBINATION;
			break;
		case 'Q':
			flags |= HS_FLAG_QUIET;
			break;
		case '{':
			ret = parse_ext_token(ptr, &ext);
			goto out;
		case '\r':
		case '\n':
		case '\0':
			ret = true;
			goto out;
		default:
			ERR("Unknown flag: '%c'", cur);
			return false;
		}
	}

	__builtin_unreachable();

out:
	if (out_flags) {
		*out_flags = flags;
	}
	if (out_ext) {
		*out_ext = ext;
	}

	return ret;
}

static bool parse_expression(const char * const in, struct pat_desc *out)
{
	char *ptr, *suff;
	unsigned long id;
	unsigned int flags;
	hs_expr_ext_t ext;

	errno = 0;
	id = strtoul(in, &ptr, 10);

	if (ptr == in || errno) {
		ERR("Unable to parse id");
		return false;
	}

	if (ptr[0] != ':' || ptr[1] != '/') {
		ERR("id not followed by \":/\"");
		return false;
	}

	ptr += 2;

	suff = strrchr(ptr, '/');
	if (suff) {
		*suff = '\0';
		suff++;

		if (!parse_flags_ext(suff, &flags, &ext)) {
			return false;
		}
	} else {
		ext = (hs_expr_ext_t){};
	}

	*out = (struct pat_desc){
		.id = id,
		.ext = ext,
		.regexp = ptr,
	};

	return true;
}

static inline bool is_empty_line(const char buf[static const 1])
{
	switch (buf[0]) {
	case '\r':
	case '\n':
	case '\0':
	case '#':
		return true;
	default:
		return false;
	}
}

static struct pat_file *read_patterns(const char *fn)
{
	static char buf[16384];
	struct pat_file *pf;
	unsigned int i;
	FILE *f;

	pf = pat_file();
	if (pf == NULL) {
		ERR("%s: pat_file: %s", fn, strerror(errno));
		goto out;
	}

	f = fopen(fn, "r");
	if (f == NULL) {
		ERR("%s: fopen: %s", fn, strerror(errno));
		goto out_free;
	}

	for (i = 0; fgets(buf, sizeof(buf), f); i++) {
		struct pat_desc desc;

		if (is_empty_line(buf))
			continue;

		if (!parse_expression(buf, &desc)) {
			ERR("%s:%u: unable to parse expression",
				fn, i + 1);
			goto out_close;
		}

		if (!pat_file_add_pat(pf, desc)) {
			goto out_close;
		}
	}

	fclose(f);
	goto out;

out_close:
	fclose(f);
out_free:
	pat_file_free(pf);
	pf = NULL;
out:
	return pf;
}

static bool write_patterns(hs_database_t *db, const char *fn)
{
	hs_error_t hsret;
	char *bytes;
	size_t length;
	FILE *f;
	bool ret = false;

	if (db) {
		hsret = hs_serialize_database(db, &bytes, &length);
		if (hsret != HS_SUCCESS) {
			ERR("hs_serialize_database: %d", hsret);
			goto out;
		}
	} else {
		bytes = NULL;
		length = 0;
	}

	f = fopen(fn, "w");
	if (f == NULL) {
		ERR("%s: fopen: %s", fn, strerror(errno));
		goto out_free;
	}

	if (db) {
		if (fwrite(bytes, length, 1, f) != 1) {
			ERR("%s: fwrite: %s", fn, strerror(errno));
			goto out_close;
		}
	}

	printf("[HS-COMPILE] %s (%zu bytes)\n", fn, length);
	ret = true;

out_close:
	fclose(f);
out_free:
	free(bytes);
out:
	return ret;
}

static bool do_compile(const char * const in_file,
			const char * const out_file,
			const unsigned int mode,
			const hs_platform_info_t * const arch)
{
	struct pat_file *pf;
	hs_database_t *db;
	bool ret = false;

	pf = read_patterns(in_file);
	if (pf == NULL) {
		ERR("failed to read paterns");
		goto out;
	}

	if (pf->nr_pats) {
		db = compile_patterns(pf, mode, arch);
		if (db == NULL) {
			ERR("failed to compile paterns");
			goto out_free_pf;
		}
	} else {
		db = NULL;
	}

	if (!write_patterns(db, out_file)) {
		goto out_free_db;
	}

	ret = true;
out_free_db:
	hs_free_database(db);
out_free_pf:
	pat_file_free(pf);
out:
	return ret;
}

#define OPT_MARCH	256
#define OPT_MTUNE	(OPT_MARCH + 256)
#define OPT_MODE	(OPT_MTUNE + 256)
#define OPT_SOM_MODE	(OPT_MODE + 256)
#define OPT_MAX		(OPT_SOM_MODE + 4)

static const struct option long_opts[] = {
	{"help", 0, 0, 'h'},
	{"native", 0, 0, 'n'},

	/* CPU feature flags */
	{"avx2", 0, 0,			OPT_MARCH + HS_CPU_FEATURES_AVX2},
	{"avx512", 0, 0,		OPT_MARCH + HS_CPU_FEATURES_AVX512},
	{"avx512vbmi", 0, 0,		OPT_MARCH + HS_CPU_FEATURES_AVX512VBMI},
	{"avx512-vbmi", 0, 0,		OPT_MARCH + HS_CPU_FEATURES_AVX512VBMI},
	{"vbmi", 0, 0,			OPT_MARCH + HS_CPU_FEATURES_AVX512VBMI},

	/* CPU architecture tuning flags */
	{"generic", 0, 0,		OPT_MTUNE + HS_TUNE_FAMILY_GENERIC},
	{"snb", 0, 0,			OPT_MTUNE + HS_TUNE_FAMILY_SNB},
	{"sandybridge", 0, 0,		OPT_MTUNE + HS_TUNE_FAMILY_SNB},
	{"ivb", 0, 0,			OPT_MTUNE + HS_TUNE_FAMILY_IVB},
	{"ivybridge", 0, 0,		OPT_MTUNE + HS_TUNE_FAMILY_IVB},
	{"hsw", 0, 0,			OPT_MTUNE + HS_TUNE_FAMILY_HSW},
	{"haswell", 0, 0,		OPT_MTUNE + HS_TUNE_FAMILY_HSW},
	{"slm", 0, 0,			OPT_MTUNE + HS_TUNE_FAMILY_SLM},
	{"silvermont", 0, 0,		OPT_MTUNE + HS_TUNE_FAMILY_SLM},
	{"bdw", 0, 0,			OPT_MTUNE + HS_TUNE_FAMILY_BDW},
	{"broadwell", 0, 0,		OPT_MTUNE + HS_TUNE_FAMILY_BDW},
	{"skl", 0, 0,			OPT_MTUNE + HS_TUNE_FAMILY_SKL},
	{"skylake", 0, 0,		OPT_MTUNE + HS_TUNE_FAMILY_SKL},
	{"skx", 0, 0,			OPT_MTUNE + HS_TUNE_FAMILY_SKX},
	{"skylake-server", 0, 0,	OPT_MTUNE + HS_TUNE_FAMILY_SKX},
	{"glm", 0, 0,			OPT_MTUNE + HS_TUNE_FAMILY_GLM},
	{"goldmont", 0, 0,		OPT_MTUNE + HS_TUNE_FAMILY_GLM},
	{"icl", 0, 0,			OPT_MTUNE + HS_TUNE_FAMILY_ICL},
	{"icelake", 0, 0,		OPT_MTUNE + HS_TUNE_FAMILY_ICL},
	{"icx", 0, 0,			OPT_MTUNE + HS_TUNE_FAMILY_ICX},
	{"icelake-server", 0, 0,	OPT_MTUNE + HS_TUNE_FAMILY_ICX},

	/* Scanning mode */
	{"block", 0, 0,			OPT_MODE + HS_MODE_BLOCK},
	{"nostream", 0, 0,		OPT_MODE + HS_MODE_NOSTREAM},
	{"stream", 0, 0,		OPT_MODE + HS_MODE_STREAM},
	{"vectored", 0, 0,		OPT_MODE + HS_MODE_VECTORED},

	/* SOM mode */
	{"som-small", 0, 0,		OPT_SOM_MODE + 0},
	{"som-medium", 0, 0,		OPT_SOM_MODE + 1},
	{"som-large", 0, 0,		OPT_SOM_MODE + 2},

	{NULL, }
};

__attribute__((noreturn))
static void usage(int val)
{
	printf("Hyperscan database compiler\n\n");
	printf("Usage:\n");
	printf("  $ %s [OPTIONS..] INFILE OUTFILE\n",
		program_invocation_name);
	printf("\n");
	printf("Options:\n");
	printf("    -n, --native            Use current CPU architecture\n");
	printf("    -h, --help              This message\n");
	printf("\n");
	printf("  Select hyperscan database mode:\n");
	printf("    --block, --nostream     (default)\n");
	printf("    --stream\n");
	printf("    --vectored\n");
	printf("\n");
	printf("  Start-of-Match precision:\n");
	printf("    --som-large             (64bit window)\n");
	printf("    --som-medium            (32bit window)\n");
	printf("    --som-small             (16bit window)\n");
	printf("\n");
	printf("  Set available CPU features (set zero or more):\n");
	printf("    --avx2\n");
	printf("    --avx512\n");
	printf("    --avx512vbmi, --avx512-vbmi, --vbmi\n");
	printf("\n");
	printf("  Chose a CPU architecture to tune for:\n");
	printf("    --generic\n");
	printf("    --snb, --sandybridge    (default)\n");
	printf("    --ivb, --ivybridge\n");
	printf("    --hsw, --haswell\n");
	printf("    --slm, --silvermont\n");
	printf("    --bdw, --broadwell\n");
	printf("    --skl, --skylake\n");
	printf("    --skx, --skylake-server\n");
	printf("    --glm, --goldmont\n");
	printf("    --icl, --icelake\n");
	printf("    --icx, --icelake-server\n");

	switch (val) {
	case 'h':
		exit(EXIT_SUCCESS);
	case ':':
		fprintf(stderr, "%s: error: Missing argument\n",
			program_invocation_short_name);
		exit(EXIT_FAILURE);
	case '?':
		fprintf(stderr, "%s: error: Unknown argument\n",
			program_invocation_short_name);
		/* fallthrough */
	default:
		exit(EXIT_FAILURE);
	}
}

static struct params parse_args(int argc, char **argv)
{
	unsigned long long march = 0;
	int mtune = HS_TUNE_FAMILY_SNB; // default to sandybridge
	unsigned int mode = 0;
	hs_platform_info_t native;
	int som_mode = -1;

	while (true) {
		int c;

		c = getopt_long(argc, argv, ":h", long_opts, NULL);
		if (c < 0)
			break;

		switch (c) {
		case 'h': /* help */
		case ':': /* missing argument */
		case '?': /* unknown option */
			usage(c);
		case 'n':
			hs_populate_platform(&native);
			mtune = native.tune;
			march = native.cpu_features;
			break;
		case OPT_MARCH ... OPT_MTUNE - 1:
			mtune |= (c - OPT_MARCH);
			break;
		case OPT_MTUNE ... OPT_MODE - 1:
			mtune = c - OPT_MTUNE;
			break;
		case OPT_MODE ... OPT_SOM_MODE - 1:
			mode |= c - OPT_MODE;
			break;
		case OPT_SOM_MODE ... OPT_MAX - 1:
			som_mode = c - OPT_SOM_MODE;
			break;
		default:
			usage('?');
		}
	}

	/* If no block/stream mode set, default to block mode */
	if (!(mode & (HS_MODE_BLOCK|HS_MODE_STREAM))) {
		mode |= HS_MODE_BLOCK;
	}

	switch (som_mode) {
	case 0:
		mode |= HS_MODE_SOM_HORIZON_SMALL;
		break;
	case 1:
		mode |= HS_MODE_SOM_HORIZON_MEDIUM;
		break;
	case 2:
		mode |= HS_MODE_SOM_HORIZON_LARGE;
		break;
	default:
		break;
	}

	argv = argv + optind;
	argc = argc - optind;

	if (unlikely(argc != 2)) {
		usage(':');
	}

	return (struct params) {
		.mode = mode,
		.arch = {
			.tune = mtune,
			.cpu_features = march,
		},
		.in_file = argv[0],
		.out_file = argv[1],
	};
}

int main(int argc, char **argv)
{
	const struct params p = parse_args(argc, argv);

	if (!do_compile(p.in_file, p.out_file, p.mode, &p.arch)) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
