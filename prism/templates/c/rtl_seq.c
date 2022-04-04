
static void /*{name}*/(prism_thread_t *st,
			const struct /*{hook.name}*/_buffers *bufs,
			struct prism_sidbuf *sidbuf)
{
	trace("/*{name}*/ BEGIN SEQUENCE\n");
// for next in insn.steps
	/*{next.name}*/(st, bufs, sidbuf);
// endfor
	trace("/*{name}*/ END SEQUENCE\n");
}
