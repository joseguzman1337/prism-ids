__attribute__((hot))
static void /*{name}*/(prism_thread_t *st,
			const struct /*{hook.name}*/_buffers *bufs,
			struct prism_sidbuf *sidbuf)
{
	bool success = false;

	trace("/*{name}*/ pcre_match /%s/\n",
		/*{insn.pcre2.regex|esc}*/);
	if (!bufs->/*{insn.buf.name.lower()}*/.len) {
		return;
	}

	const int ret = pcre2_match(/*{insn.pcre2.cvar_code}*/,
				(PCRE2_SPTR8)bufs->/*{insn.buf.name.lower()}*/.ptr,
				bufs->/*{insn.buf.name.lower()}*/.len,
				0, /* start_offset */
				0, /* options */
				NULL,
				NULL);
	if (ret >= 0) {
		success = true;
	} else if (ret == PCRE2_ERROR_NOMATCH) {
		success = false;
	}

	if (success) {
		/*{insn.on_match.name}*/(st, bufs, sidbuf);
	}
}
