
static void /*{name}*/(prism_thread_t *st,
			const struct /*{hook.name}*/_buffers *bufs,
			struct prism_sidbuf *sidbuf)
{
	size_t offset;

	if (bufs->/*{insn.buf.name.lower()}*/.len < /*{insn.content|len}*/)
		return;

	offset = bufs->/*{insn.buf.name.lower()}*/.len - /*{insn.content|len}*/;
	if (likely(memcmp(bufs->/*{insn.buf.name.lower()}*/.ptr + offset,
			/*{insn.content|cstr}*/,
			/*{insn.content|len}*/)))
		return;
	/*{insn.on_match.name}*/(st, bufs, sidbuf);
}
