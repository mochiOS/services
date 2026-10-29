#if defined(PROVIDER)
.data
.global payload
.type payload,@object
.size payload,23
payload: .zero 23
.global absolute_object
.type absolute_object,@object
.set absolute_object,0x123456
.size absolute_object,91
.section .tdata,"awT",@progbits
.global tls_payload
.type tls_payload,@tls_object
.size tls_payload,13
tls_payload: .zero 13
#elif defined(ROOT)
.text
.global _start
.type _start,@function
_start: ret
#ifdef WEAK_DEFINED
.data
.weak missing
.type missing,@object
.size missing,7
missing: .zero 7
#endif
#ifdef PREEMPT
.data
.global payload
.type payload,@object
.size payload,41
payload: .zero 41
#endif
#else
.data
#ifdef STANDALONE
.global payload
.type payload,@object
.size payload,23
payload: .zero 23
#endif
.weak missing
.type missing,@object
.global size64,size32,canary,weak_size,absolute_size,wrap_size,tls_size
.type size64,@object
.size size64,8
size64: .quad payload@SIZE+7
.type size32,@object
.size size32,4
size32: .long payload@SIZE-3
canary: .long 0xdeadbeef
weak_size: .quad missing@SIZE+5
#ifndef STANDALONE
absolute_size: .quad absolute_object@SIZE+3
.type tls_payload,@tls_object
tls_size: .quad tls_payload@SIZE+9
#endif
wrap_size: .quad payload@SIZE-60
.text
.global measure
.type measure,@function
measure:
 mov size64@GOTPCREL(%rip),%rax
 mov (%rax),%rax
 ret
.size measure,.-measure
#ifdef STANDALONE
.global _start
.type _start,@function
_start: ret
#endif
#endif
.section .note.GNU-stack,"",@progbits
