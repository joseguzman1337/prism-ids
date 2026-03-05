
static void entry_/*{hook.name}*/_/*{buf_name}*/(prism_thread_state_t *st,
			hs_scratch_t *scratch,
			size_t buf_len,
			const char buf[static buf_len],
			struct prism_sidbuf *sidbuf)
{
	trace(" == /*{buf_name}*/\n");
	/*{entry.name}*/(st, scratch, buf_len, buf, sidbuf);
}
