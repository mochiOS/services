#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
static void *special;
static void check(int value) { if (!value) { fputs("lookup oracle failed\n", stderr); exit(1); } }
static void *thread(void *unused) {
    (void)unused;
    int *value=dlsym(special,"thread_data"); check(value && *value==13); *value=25; return NULL;
}
int main(int argc,char **argv) {
    check(argc==3);
    void *versions=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);check(versions!=NULL);
    int *current=dlsym(versions,"api_data"),*old=dlvsym(versions,"api_data","API_1");
    check(current&&old&&*current==29&&*old==7);
    int (*call)(int)=dlsym(versions,"api_call");check(call&&call(1)==30);
    call=dlvsym(versions,"api_call","API_1");check(call&&call(1)==8);
    dlerror();check(dlvsym(versions,"api_call","MISSING")==NULL);check(dlerror()!=NULL);
    special=dlopen(argv[2],RTLD_NOW|RTLD_LOCAL);check(special!=NULL);
    int (*selected)(void)=dlsym(special,"selected");check(selected&&selected()==73);
    dlerror();check(dlsym(special,"null_selected")==NULL);check(dlerror()==NULL);
    dlerror();check(dlsym(special,"absolute_zero")==NULL);check(dlerror()==NULL);
    int *value=dlsym(special,"thread_data");check(value&&*value==13);*value=91;
    pthread_t child;check(pthread_create(&child,NULL,thread,NULL)==0);check(pthread_join(child,NULL)==0);check(*value==91);
    check(dlclose(special)==0&&dlclose(versions)==0);
    puts("exports: default/old/new/TLS/IFUNC/zero/missing PASS");return 0;
}
