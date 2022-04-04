
static void /*{name}*/(prism_thread_t *st,
			const struct /*{hook.name}*/_buffers *bufs,
			struct prism_sidbuf *sidbuf)
{
	trace("/*{name}*/ buf_exact /*{insn.buf.name}*/\n");
	if (likely(bufs->/*{insn.buf.name.lower()}*/.len != /*{insn.content|len}*/))
		return;
	if (likely(memcmp(bufs->/*{insn.buf.name.lower()}*/.ptr,
			/*{insn.content|cstr}*/,
			/*{insn.content|len}*/)))
		return;
	/*{insn.on_match.name}*/(st, bufs, sidbuf);
}
