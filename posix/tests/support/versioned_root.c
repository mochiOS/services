#ifdef UNVERSIONED_REFERENCE
extern int api_call(int);
extern int api_data;
int _start(void) { return api_call(1) + api_data; }
#else
extern int legacy_call(int);
extern int current_call(int);
extern int legacy_data;
extern int current_data;
__asm__(".symver legacy_call,api_call@API_1");
__asm__(".symver current_call,api_call@API_2");
__asm__(".symver legacy_data,api_data@API_1");
__asm__(".symver current_data,api_data@API_2");
#ifdef ROOT_PREEMPTION
int api_call(int value) { return 500 + value; }
int api_data = 99;
#endif
int _start(void) {
    return legacy_call(1) + current_call(2) + legacy_data + current_data;
}
#ifdef VERSIONED_TLS
extern __thread int legacy_tls;
extern __thread int current_tls;
__asm__(".symver legacy_tls,api_tls@API_1");
__asm__(".symver current_tls,api_tls@API_2");
int read_tls(void) { return legacy_tls + current_tls; }
#endif
#endif
