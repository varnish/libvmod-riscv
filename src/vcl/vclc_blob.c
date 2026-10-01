/*
 * The sandboxed VCL compiler (vcl/vclc.elf), embedded in the VMOD so that
 * building or running it needs no Rust or RISC-V toolchain. The assembler
 * finds the blob through -Wa,-I<top_srcdir>/vcl; both build systems add
 * that flag and a dependency on the blob for this file.
 */
__asm__(
	"	.section .rodata\n"
	"	.global vclc_elf\n"
	"	.hidden vclc_elf\n"
	"	.balign 16\n"
	"vclc_elf:\n"
	"	.incbin \"vclc.elf\"\n"
	"	.global vclc_elf_end\n"
	"	.hidden vclc_elf_end\n"
	"vclc_elf_end:\n"
	"	.previous\n"
);
