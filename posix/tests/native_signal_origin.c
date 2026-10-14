#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

enum { INHERITED = 628, CALL = 632, INSTALL = 654, RETURN = 655,
       ORIGIN = 84, FAULT = 83, RAISE = 68, DEQUEUE = 66, COMPLETE = 51 };
static unsigned char entry_stack[16384] __attribute__((aligned(16)));
static uint64_t endpoint, request_id;

static int64_t native(uint64_t n, uint64_t a, uint64_t b, uint64_t c,
                      uint64_t d, uint64_t e, uint64_t f) {
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(n)
                     : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return (int64_t)n;
}

static uint32_t get32(const void *p) { uint32_t v; memcpy(&v,p,4); return v; }
static uint64_t get64(const void *p) { uint64_t v; memcpy(&v,p,8); return v; }
static void put32(void *p,uint32_t v) { memcpy(p,&v,4); }
static void put64(void *p,uint64_t v) { memcpy(p,&v,8); }

static int request(unsigned opcode, const void *payload, unsigned length, unsigned char *output, unsigned expected) {
    unsigned char bytes[64] = {0}, reply[64] = {0};
    struct { uint32_t count, flags; struct {uint32_t handle, reserved; uint64_t rights;} entries[4]; } handles = {0};
    memcpy(bytes,"POSX",4); bytes[4]=1; bytes[6]=opcode;
    put64(bytes+8,++request_id); put32(bytes+20,length);
    if (length) memcpy(bytes+32,payload,length);
    int64_t result = native(CALL,endpoint,(uintptr_t)bytes,32+length,(uintptr_t)reply,sizeof(reply),(uintptr_t)&handles);
    if (result < 0 || (uint32_t)result < 32 || handles.count || handles.flags ||
        memcmp(reply,"POSX",4) || reply[4]!=1 || reply[6]!=0 || reply[7]!=0x80 || get64(reply+8)!=request_id) return -999;
    int32_t status=(int32_t)get32(reply+24);
    if (status) return status;
    if (get32(reply+20)!=expected || (uint32_t)result!=32+expected) return -998;
    if (expected) memcpy(output,reply+32,expected);
    return 0;
}

static void interrupt_only(uint64_t payload, uint64_t token) {
    (void)payload;
    native(RETURN,token,0,0,0,0,0);
    _exit(90);
}

#define CHECK(test) do { if (!(test)) {fprintf(stderr,"signal-origin: FAIL line=%d\n",__LINE__); return 1;} } while(0)

int main(void) {
    sigset_t empty; sigemptyset(&empty);
    CHECK(sigprocmask(SIG_SETMASK,&empty,NULL)==0);
    uint64_t key; memcpy(&key,"POSXCTRL",8);
    int64_t control=native(INHERITED,key,0,0,0,0,0);
    CHECK(control>0); endpoint=control;
    struct {uint64_t entry,base,length,flags,reserved[4];} config={
        (uintptr_t)interrupt_only,(uintptr_t)entry_stack,sizeof(entry_stack),0,{0}
    };
    CHECK(native(INSTALL,(uintptr_t)&config,sizeof(config),0,0,0,0)==0);
    unsigned char signal[16]={0},delivery[16],origin[16];
    put32(signal+8,30);
    CHECK(request(RAISE,signal,16,NULL,0)==0);
    CHECK(request(DEQUEUE,NULL,0,delivery,16)==0 && get32(delivery)==30 && get64(delivery+8));
    CHECK(request(ORIGIN,delivery,16,origin,16)==0);
    CHECK(get32(origin)==1 && get32(origin+4)==(uint32_t)getuid() && get64(origin+8)==(uint64_t)getpid());
    sigset_t children; sigemptyset(&children); sigaddset(&children,SIGCHLD);
    CHECK(sigprocmask(SIG_BLOCK,&children,NULL)==0);
    pid_t child=fork(); CHECK(child>=0);
    if (!child) _exit(request(ORIGIN,delivery,16,origin,16)==-11 ? 0 : 91);
    int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
    CHECK(request(ORIGIN,delivery,16,origin,16)==0);
    CHECK(request(COMPLETE,delivery,16,NULL,0)==0);
    CHECK(request(ORIGIN,delivery,16,origin,16)==-11);
    unsigned char mask[16]={0}, child_delivery[16]; put32(mask,1);
    CHECK(request(65,mask,16,origin,8)==0);
    CHECK(request(DEQUEUE,NULL,0,child_delivery,16)==0 && get32(child_delivery)==SIGCHLD);
    CHECK(request(ORIGIN,child_delivery,16,origin,16)==0);
    CHECK(get32(origin)==2 && get32(origin+4)==(uint32_t)getuid() && get64(origin+8)==(uint64_t)child);
    CHECK(request(COMPLETE,child_delivery,16,NULL,0)==0);
    CHECK(sigprocmask(SIG_SETMASK,&empty,NULL)==0);
    unsigned char fault[24]; put32(signal+8,SIGSEGV);
    CHECK(request(FAULT,signal,16,fault,24)==0);
    CHECK(request(ORIGIN,fault,16,origin,16)==0);
    CHECK(get32(origin)==4 && get32(origin+4)==0 && get64(origin+8)==0);
    CHECK(request(COMPLETE,fault,16,NULL,0)==0);
    puts("signal-origin: PASS authenticated sender, real uid, owner-only lookup, token lifetime and fault provenance");
    return 0;
}
