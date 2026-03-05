.section .rodata
// for path, hsdb in hsdbs.items()

	.align 8
	.globl /*{hsdb.cvar_bin}*/
	.type /*{hsdb.cvar_bin}*/, @object
/*{hsdb.cvar_bin}*/:
	.incbin "/*{path}*/"
/*{hsdb.asmvar_end}*/:

// endfor

// for hsdb in hsdbs.values()

	.align 8
	.globl /*{hsdb.cvar_size}*/
	.type /*{hsdb.cvar_size}*/, @object
/*{hsdb.cvar_size}*/:
	.quad /*{hsdb.asmvar_end}*/ - /*{hsdb.cvar_bin}*/

// endfor
