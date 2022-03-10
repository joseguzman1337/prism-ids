
__attribute__((used))
static int on_hs_match_/*{name}*/(unsigned int id,
				unsigned long long from,
				unsigned long long to,
				unsigned int flags,
				void *priv)
{
	bool *flag = priv;

	trace("HYPERSCAN MATCH id=%u %llu:%llu\n", id, from, to);
	assert(id == 0);
	*flag = true;
	return 1; /* done matching */
}

__attribute__((hot))
static void /*{name}*/(prism_thread_t *st,
			const struct /*{hook.name}*/_buffers *bufs,
			struct prism_sidbuf *sidbuf)
{
	bool matched = false;
	hs_error_t ret;

	trace("/*{name}*/ hs_scan /*{insn.hsdb.cvar_db}*/\n");
	if (!bufs->/*{insn.buf.name.lower()}*/.len) {
		return;
	}
	ret = hs_scan(/*{insn.hsdb.cvar_db}*/,
		bufs->/*{insn.buf.name.lower()}*/.ptr,
		bufs->/*{insn.buf.name.lower()}*/.len,
		0,
		st->scratch,
		on_hs_match_/*{name}*/,
		&matched);
	assert(ret == HS_SUCCESS || ret == HS_SCAN_TERMINATED);

	if (!matched) {
		trace(" --> /*{name}*/: no match: %s\n",
			/*{insn.pattern.pattern|esc}*/);
		return;
	}

	trace(" --> /*{name}*/: match: %s\n",
		/*{insn.pattern.pattern|esc}*/);
	/*{insn.on_match.name}*/(st, bufs, sidbuf);
}
