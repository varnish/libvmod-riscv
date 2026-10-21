/*
 * The QuickJS guest (program/js.elf), embedded in the VMOD so that a tenant
 * can be a .js file without a RISC-V toolchain or a program file. Both build
 * systems define JS_ELF_PATH as the blob's absolute path, which LTO needs
 * since it assembles this at link time, and add a dependency on the blob.
 */
__asm__(
	"	.section .rodata\n"
	"	.global js_elf\n"
	"	.hidden js_elf\n"
	"	.balign 16\n"
	"js_elf:\n"
	"	.incbin \"" JS_ELF_PATH "\"\n"
	"	.global js_elf_end\n"
	"	.hidden js_elf_end\n"
	"js_elf_end:\n"
	"	.previous\n"
);
