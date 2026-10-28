/* Test-only dynamic ET_EXEC layout using the existing static SDK. The source
 * PHDR table is deliberately outside LOAD, like the SDK's normal layout. */
OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)
PHDRS {
    text PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
    dynamic PT_DYNAMIC FLAGS(6);
    stack PT_GNU_STACK FLAGS(6);
}
SECTIONS {
    . = 0x400000;
    .text : ALIGN(4K) {
        KEEP(*(.text._start))
        *(.text .text.* .plt .plt.* .iplt)
    } :text
    .rodata : ALIGN(4K) { *(.rodata .rodata.* .eh_frame_hdr .eh_frame) } :rodata
    .hash : { *(.hash) } :rodata
    .gnu.hash : { *(.gnu.hash) } :rodata
    .dynsym : { *(.dynsym) } :rodata
    .dynstr : { *(.dynstr) } :rodata
    .rela.dyn : { *(.rela.dyn) } :rodata
    .rela.plt : { *(.rela.plt) } :rodata
    .preinit_array : ALIGN(8) {
        PROVIDE_HIDDEN(__preinit_array_start = .);
        KEEP(*(.preinit_array))
        PROVIDE_HIDDEN(__preinit_array_end = .);
    } :rodata
    .init_array : ALIGN(8) {
        PROVIDE_HIDDEN(__init_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
        KEEP(*(.init_array EXCLUDE_FILE(*crtend*.o *crtbegin*.o) .ctors))
        PROVIDE_HIDDEN(__init_array_end = .);
    } :rodata
    .fini_array : ALIGN(8) {
        PROVIDE_HIDDEN(__fini_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
        KEEP(*(.fini_array EXCLUDE_FILE(*crtend*.o *crtbegin*.o) .dtors))
        PROVIDE_HIDDEN(__fini_array_end = .);
    } :rodata
    .data : ALIGN(4K) {
        HIDDEN(__mochios_data_start = .);
        *(.data .data.*)
    } :data
    .got : { *(.got .got.* .igot.*) } :data
    .dynamic : { *(.dynamic) } :data :dynamic
    .tdata : ALIGN(16) { *(.tdata .tdata.*) } :data
    .tbss : ALIGN(16) { *(.tbss .tbss.*) } :data
    .bss : ALIGN(4K) { *(COMMON) *(.bss .bss.*) } :data
    HIDDEN(__mochios_data_end = .);
    _end = .;
    /DISCARD/ : { *(.comment .note*) }
}
