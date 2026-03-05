
static void /*{name}*/(prism_thread_state_t *st,
			hs_scratch_t *scratch,
			size_t buf_len,
			const char buf[static buf_len],
			struct prism_sidbuf *sidbuf)
{
// if insn.has_partials
	trace("/*{name}*/: set state bit /*{insn.set_bit}*/\n");
	state_bit_set(st, /*{insn.set_bit}*/);
// endif

// for sid, bits in insn.finals
	trace("/*{name}*/: checking bits /*{bits}*/ for sid /*{sid}*/\n");
	if (/*{bits | map("state_bit_isset") | join(" && ")}*/) {
		prism_match_sid(/*{sid}*/, sidbuf);
	}
// endfor
}
