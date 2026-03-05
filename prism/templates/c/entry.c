
void entry_/*{hook.name}*/(prism_thread_state_t *st, hs_scratch_t *scratch, const struct /*{hook.name}*/_buffers *bufs, struct prism_sidbuf *sidbuf)
{
	trace("ENTERING /*{hook.name}*/\n");
#if PRISM_STATE_BITS
	memset(st->state_bits, 0, sizeof(st->state_bits));
#endif
// for buf_name in buf_names
	entry_/*{hook.name}*/_/*{buf_name}*/(st,
			scratch,
			bufs->/*{buf_name}*/.len,
			bufs->/*{buf_name}*/.ptr,
			sidbuf);
//endfor
	trace("\n");
}
