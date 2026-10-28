int old_data = 7;
int new_data = 29;
int old_call(int value) { return value + old_data; }
int new_call(int value) { return value + new_data; }
__asm__(".symver old_call,api_call@API_1");
__asm__(".symver new_call,api_call@@API_2");
__asm__(".symver old_data,api_data@API_1");
__asm__(".symver new_data,api_data@@API_2");
#ifdef VERSIONED_TLS
__thread int old_tls = 13;
__thread int new_tls = 37;
__asm__(".symver old_tls,api_tls@API_1");
__asm__(".symver new_tls,api_tls@@API_2");
#endif
