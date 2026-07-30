ENTRY(_start)

SECTIONS
{
  . = 0x200000;
  .text : ALIGN(4096) { *(.text .text.*) }
  .rodata : ALIGN(4096) { *(.rodata .rodata.*) }
  .data : ALIGN(4096) { *(.data .data.*) }
  .bss : ALIGN(4096) { *(.bss .bss.* COMMON) }
  /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment) }
}
