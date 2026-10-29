/* Syscall-free resolver fixtures. All observed state belongs to these LOADs. */
#ifdef PROVIDER
.data
.globl seed
.type seed,@object
seed: .quad 73
.size seed,8
.globl provider_calls
.hidden provider_calls
provider_calls: .quad 0
.text
.globl choose
.type choose,@gnu_indirect_function
choose:
    incq provider_calls(%rip)
    mov seed@GOTPCREL(%rip),%rax
    cmpq $73,(%rax)
    jne 1f
    lea provider_impl(%rip),%rax
    ret
1:  xor %eax,%eax
    ret
.size choose,.-choose
.globl choose_plt
.type choose_plt,@gnu_indirect_function
.set choose_plt,choose
.type provider_impl,@function
provider_impl:
    mov $73,%eax
    ret
.size provider_impl,.-provider_impl
#endif

#ifdef MIDDLE
#ifdef READONLY_SLOTS
.section .rodata.ifunc,"a",@progbits
#else
.data
#endif
.globl public_slot
.type public_slot,@object
public_slot: .quad choose
.size public_slot,8
#ifdef MANY_FIXUPS
.rept 160
    .quad choose
.endr
#endif
.globl local_slot
.type local_slot,@object
local_slot: .quad local_choose
.size local_slot,8
.globl zero_slot
.type zero_slot,@object
zero_slot: .quad zero_choose
.size zero_slot,8
.data
.globl local_calls
.hidden local_calls
local_calls: .quad 0
.globl seen_during_resolve
.hidden seen_during_resolve
seen_during_resolve: .quad 0
.text
.globl call_got
.type call_got,@function
call_got:
    jmp *choose@GOTPCREL(%rip)
.size call_got,.-call_got
.globl call_plt
.type call_plt,@function
call_plt:
    jmp choose_plt@PLT
.size call_plt,.-call_plt
.globl call_local
.type call_local,@function
call_local:
    jmp local_choose@PLT
.size call_local,.-call_local
.type local_choose,@gnu_indirect_function
local_choose:
    incq local_calls(%rip)
    sub $8,%rsp
    call *choose@GOTPCREL(%rip)
    add $8,%rsp
    mov %rax,seen_during_resolve(%rip)
    lea local_impl(%rip),%rax
    ret
.size local_choose,.-local_choose
.type local_impl,@function
local_impl:
    mov $7,%eax
    ret
.size local_impl,.-local_impl
.type zero_choose,@gnu_indirect_function
zero_choose:
    xor %eax,%eax
    ret
.size zero_choose,.-zero_choose
.globl get_seen
.type get_seen,@function
get_seen:
    mov seen_during_resolve(%rip),%rax
    ret
.size get_seen,.-get_seen
.globl get_local_calls
.type get_local_calls,@function
get_local_calls:
    mov local_calls(%rip),%rax
    ret
.size get_local_calls,.-get_local_calls
#endif

#ifdef ROOT
#ifdef RELRO_CONTRACT
.text
.globl __mochios_relro_v1
.type __mochios_relro_v1,@function
__mochios_relro_v1:
    mov $1,%eax
    ret
.size __mochios_relro_v1,.-__mochios_relro_v1
#endif
#ifdef WRITABLE_CONTRACT
.text
.globl __mochios_relro_v2
.type __mochios_relro_v2,@function
__mochios_relro_v2:
    mov $2,%eax
    ret
.size __mochios_relro_v2,.-__mochios_relro_v2
#endif
.text
#ifdef CRT_CONTRACT
.globl __mochios_indirect_v1
.type __mochios_indirect_v1,@function
__mochios_indirect_v1:
    mov $1,%eax
    ret
.size __mochios_indirect_v1,.-__mochios_indirect_v1
#ifdef LARGE_METADATA
.globl __mochios_startup_metadata_v1
.type __mochios_startup_metadata_v1,@function
__mochios_startup_metadata_v1:
    mov $1,%eax
    ret
.size __mochios_startup_metadata_v1,.-__mochios_startup_metadata_v1
#endif
#ifdef LATE_CALLBACKS
.globl __mochios_lifecycle_v1
.type __mochios_lifecycle_v1,@function
__mochios_lifecycle_v1:
    mov $1,%eax
    ret
.size __mochios_lifecycle_v1,.-__mochios_lifecycle_v1
#ifdef DEFERRED_LIFECYCLE
.globl __mochios_lifecycle_v2
.type __mochios_lifecycle_v2,@function
__mochios_lifecycle_v2:
    mov $2,%eax
    ret
.size __mochios_lifecycle_v2,.-__mochios_lifecycle_v2
#endif
.section .init_array,"aw"
    .quad choose
#ifdef DEFERRED_LIFECYCLE
.section .fini_array,"aw"
    .quad choose
#endif
.text
#endif
#endif
.globl _start
.type _start,@function
_start:
    push %rbx
    call call_plt@PLT
    mov %eax,%ebx
    call call_got@PLT
    add %eax,%ebx
    call call_local@PLT
    add %ebx,%eax
    pop %rbx
    ret
.size _start,.-_start
#if defined(OVERRIDE_ORDINARY) || defined(OVERRIDE_IFUNC)
.globl choose
#ifdef OVERRIDE_IFUNC
.type choose,@gnu_indirect_function
choose:
    lea override_impl(%rip),%rax
    ret
.size choose,.-choose
override_impl:
#else
.type choose,@function
choose:
#endif
    mov $99,%eax
    ret
.globl choose_plt
.set choose_plt,choose
#endif
#endif
.section .note.GNU-stack,"",@progbits
