#include <unistd.h>
#include <stdlib.h>
#include <mochi/executable.h>
int main(int argc,char **argv){const char text[]=MESSAGE;int fd=argc>1?atoi(argv[1]):1;return write(fd,text,sizeof(text)-1)==sizeof(text)-1?0:7;}
