#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define VALUE(name) printf("%s=%lld\n", #name, (long long)(name))
#define SIZE(type) printf("sizeof(%s)=%zu\n", #type, sizeof(type))
#define ALIGN(type) printf("alignof(%s)=%zu\n", #type, _Alignof(type))
#define OFFSET(type, field) printf("%s.%s=%zu\n", #type, #field, offsetof(type, field))

_Static_assert(_Generic(&sendmsg, ssize_t (*)(int, const struct msghdr *, int): 1, default: 0), "sendmsg signature");
_Static_assert(_Generic(&recvmsg, ssize_t (*)(int, struct msghdr *, int): 1, default: 0), "recvmsg signature");
_Static_assert(_Generic(&accept4, int (*)(int, struct sockaddr *, socklen_t *, int): 1, default: 0), "accept4 signature");

int main(void) {
  VALUE(AF_UNSPEC); VALUE(AF_UNIX); VALUE(AF_LOCAL); VALUE(AF_INET); VALUE(AF_INET6);
  VALUE(PF_UNSPEC); VALUE(PF_UNIX); VALUE(PF_LOCAL); VALUE(PF_INET); VALUE(PF_INET6);
  VALUE(SOCK_STREAM); VALUE(SOCK_DGRAM); VALUE(SOCK_SEQPACKET); VALUE(SOCK_NONBLOCK); VALUE(SOCK_CLOEXEC);
  VALUE(SOL_SOCKET); VALUE(SO_DEBUG); VALUE(SO_REUSEADDR); VALUE(SO_TYPE); VALUE(SO_ERROR);
  VALUE(SO_DONTROUTE); VALUE(SO_BROADCAST); VALUE(SO_SNDBUF); VALUE(SO_RCVBUF);
  VALUE(SO_KEEPALIVE); VALUE(SO_OOBINLINE); VALUE(SO_LINGER); VALUE(SO_REUSEPORT);
  VALUE(SO_RCVLOWAT); VALUE(SO_SNDLOWAT); VALUE(SO_RCVTIMEO); VALUE(SO_SNDTIMEO);
  VALUE(SO_TIMESTAMP); VALUE(SO_ACCEPTCONN); VALUE(SOMAXCONN);
  VALUE(SHUT_RD); VALUE(SHUT_WR); VALUE(SHUT_RDWR);
  VALUE(SCM_RIGHTS); VALUE(MSG_OOB); VALUE(MSG_PEEK); VALUE(MSG_DONTROUTE);
  VALUE(MSG_CTRUNC); VALUE(MSG_TRUNC); VALUE(MSG_DONTWAIT); VALUE(MSG_WAITALL);
  VALUE(MSG_NOSIGNAL); VALUE(MSG_MORE); VALUE(MSG_CMSG_CLOEXEC);
  VALUE(FIONBIO);
  SIZE(sa_family_t); SIZE(socklen_t);
  SIZE(struct sockaddr); ALIGN(struct sockaddr); OFFSET(struct sockaddr, sa_data);
  SIZE(struct sockaddr_un); ALIGN(struct sockaddr_un); OFFSET(struct sockaddr_un, sun_path);
  SIZE(struct iovec); ALIGN(struct iovec); OFFSET(struct iovec, iov_base); OFFSET(struct iovec, iov_len);
  SIZE(struct msghdr); ALIGN(struct msghdr);
  OFFSET(struct msghdr, msg_name); OFFSET(struct msghdr, msg_namelen);
  OFFSET(struct msghdr, msg_iov); OFFSET(struct msghdr, msg_iovlen);
  OFFSET(struct msghdr, msg_control); OFFSET(struct msghdr, msg_controllen); OFFSET(struct msghdr, msg_flags);
  SIZE(struct cmsghdr); ALIGN(struct cmsghdr);
  OFFSET(struct cmsghdr, cmsg_len); OFFSET(struct cmsghdr, cmsg_level); OFFSET(struct cmsghdr, cmsg_type);
  for (unsigned length = 0; length <= 1012; length++)
    printf("space=%zu,len=%zu\n", CMSG_SPACE(length), CMSG_LEN(length));
  struct cmsghdr payload_header = {0};
  printf("data=%zu\n", (size_t)(CMSG_DATA(&payload_header) - (unsigned char *)&payload_header));
  size_t bounds[] = {0, 1, 15, 16, 17, 23, 24, 31, 32, 39, 40, 44, 64, 128};
  size_t sizes[] = {0, 1, 15, 16, 17, 20, 24, 40, 64, 128, SIZE_MAX, SIZE_MAX - 7};
  size_t positions[] = {0, 8, 16, 112, 120, 128};
  for (unsigned b = 0; b < sizeof(bounds)/sizeof(*bounds); b++)
    for (unsigned s = 0; s < sizeof(sizes)/sizeof(*sizes); s++)
      for (unsigned p = 0; p < sizeof(positions)/sizeof(*positions); p++) {
        union { size_t alignment; unsigned char bytes[128]; } data = {0};
        unsigned char *base = data.bytes;
        struct msghdr message = {0};
        message.msg_control = base; message.msg_controllen = bounds[b];
        struct cmsghdr *header = (struct cmsghdr *)(base + positions[p]);
        if (positions[p] + sizeof(*header) <= sizeof(data)) header->cmsg_len = sizes[s];
        struct cmsghdr *first = CMSG_FIRSTHDR(&message), *next = CMSG_NXTHDR(&message, header);
        printf("first=%zu,next=%zu\n", first ? (size_t)((unsigned char *)first - base) : SIZE_MAX,
               next ? (size_t)((unsigned char *)next - base) : SIZE_MAX);
      }
  struct msghdr message = {0};
  message.msg_controllen = 128;
  if (CMSG_FIRSTHDR(&message) || CMSG_NXTHDR(&message, NULL)) return 1;
  return 0;
}
