struct CopyBox {
  int *value;
  long marker;
  char text[13];
};
struct CopySelf {
  struct CopySelf *self;
  long marker;
};
extern int legacy_data;
extern int current_data;
__asm__(".symver legacy_data,api_data@API_1");
__asm__(".symver current_data,api_data@API_2");
extern struct CopyBox copy_box;
extern struct CopySelf copy_self;
extern unsigned char copy_zero[8193];
extern unsigned char copy_partial[7];
extern void *provider_address(int);
extern int provider_sum(void);
extern long provider_marker(void);
int check_copy(void);
