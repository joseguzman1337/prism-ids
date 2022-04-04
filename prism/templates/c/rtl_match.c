
__attribute__((always_inline))
static inline void /*{name}*/(prism_thread_t *st,
			const struct /*{hook.name}*/_buffers *bufs,
			struct prism_sidbuf *sidbuf)
{
// for sid in insn.sids|sorted
	trace("match /*{sid}*/\n");
	prism_match_sid(/*{sid}*/, sidbuf);
// endfor
}
