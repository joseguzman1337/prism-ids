
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
		/*{next.name}*/(shim->st, shim->bufs, shim->sidbuf);
		break;
// endfor
	}
	return 0; /* keep matching */
}

__attribute__((hot))
static void /*{name}*/(prism_thread_t *st,
			const struct /*{hook.name}*/_buffers *bufs,
			struct prism_sidbuf *sidbuf)
{
	struct hs_shim shim = {
		.st = st,
		.bufs = bufs,
		.sidbuf = sidbuf,
	};

	trace("/*{name}*/ hs_scan /*{insn.hsdb.cvar_db}*/\n");
	hs_scan(/*{insn.hsdb.cvar_db}*/,
		bufs->/*{insn.buf.name.lower()}*/.ptr,
		bufs->/*{insn.buf.name.lower()}*/.len,
		0,
		st->scratch,
		on_hs_match_/*{name}*/,
		&shim);
}
