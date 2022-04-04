
void entry_/*{hook.name}*/(prism_thread_t *st,
			const struct /*{hook.name}*/_buffers *bufs,
			struct prism_sidbuf *sidbuf)
{
	trace("ENTERING /*{hook.name}*/\n");
	/*{entry}*/(st, bufs, sidbuf);
	trace("\n");
}
