
static void /*{name}*/(prism_thread_state_t *st,
			hs_scratch_t *scratch,
			size_t buf_len,
			const char buf[static buf_len],
			struct prism_sidbuf *sidbuf)
{
	trace("/*{name}*/ BEGIN SEQUENCE\n");
// for next in insn.steps
	/*{next.name}*/(st, scratch, buf_len, buf, sidbuf);
// endfor
	trace("/*{name}*/ END SEQUENCE\n");
}
