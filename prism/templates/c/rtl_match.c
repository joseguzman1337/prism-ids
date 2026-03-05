
__attribute__((always_inline))
static inline void /*{name}*/(prism_thread_state_t *st,
			hs_scratch_t *scratch,
			size_t buf_len,
			const char buf[static buf_len],
			struct prism_sidbuf *sidbuf)
{
// for sid in insn.sids|sorted
	trace("match /*{sid}*/\n");
	prism_match_sid(/*{sid}*/, sidbuf);
// endfor
}
