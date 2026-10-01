ENTRY(_start)

/* Two segments, not one.  libriscv decodes and binary-translates every
   executable segment in full, and only shrinks one to its `.text` *section*
   when that section is the ELF's only `.text` — which it is not once this
   image is copied into a policy ELF that has its own.  Constant tables left
   inside an RX segment are therefore decoded as instructions: 704 bytes of
   weekday/month/digit tables produced 110 illegal opcodes and 93 phantom
   floating-point instructions in one translated region. */
PHDRS {
  text   PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
}

SECTIONS {
  . = 0x100000;
  .text : {
    KEEP(*(.text.start))
    *(.text .text.*)
  } :text
  . = ALIGN(0x1000);
  .rodata : { *(.rodata .rodata.*) } :rodata
  /DISCARD/ : { *(.runtime.keep) *(.eh_frame*) *(.comment) *(.note*) }
}
