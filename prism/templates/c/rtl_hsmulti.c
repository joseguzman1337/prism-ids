
__attribute__((used))
static int on_hs_match_/*{name}*/(unsigned int id,
				unsigned long long from,
				unsigned long long to,
				unsigned int flags,
				void *priv)
{
	const struct hs_shim *shim = priv;

	trace("HYPERSCAN MATCH id=%u %llu:%llu\n", id, from, to);
	switch (id) {
// for val, next in insn.mapping()
	case /*{val}*/:
		trace(" --> /*{name}*/: val /*{val}*/\n");
		/*{next.name}*/(shim->st, shim->scratch, shim->buf_len, shim->buf, shim->sidbuf);
		break;
// endfor
	}
	return 0; /* keep matching */
}

__attribute__((hot))
static void /*{name}*/(prism_thread_state_t *st,
			hs_scratch_t *scratch,
			size_t buf_len,
			const char buf[static buf_len],
			struct prism_sidbuf *sidbuf)
{
	struct hs_shim shim = {
		.st = st,
		.scratch = scratch,
		.buf_len = buf_len,
		.buf = buf,
		.sidbuf = sidbuf,
	};

	trace("/*{name}*/ hs_scan /*{insn.hsdb.cvar_db}*/\n");
	hs_scan(/*{insn.hsdb.cvar_db}*/,
		buf,
		buf_len,
		0,
		scratch,
		on_hs_match_/*{name}*/,
		&shim);
}
