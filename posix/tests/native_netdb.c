/* Compile against the public mochiOS headers, then execute with the real
 * newlib runtime and POSIX endpoints. No host resolver is linked here. */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "netdb-c: line %d failed: %s (errno %d)\n", __LINE__,    \
              #condition, errno);                                              \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

_Static_assert(sizeof(struct addrinfo) == 48, "addrinfo size");
_Static_assert(offsetof(struct addrinfo, ai_addr) == 24, "addrinfo address");
_Static_assert(offsetof(struct addrinfo, ai_canonname) == 32,
               "addrinfo canonical");
_Static_assert(AI_NUMERICSERV == 1024 && AI_ADDRCONFIG == 32, "AI flags");
_Static_assert(NI_NUMERICHOST == 1 && NI_NAMEREQD == 8, "NI flags");
_Static_assert(EAI_SYSTEM == -11 && EAI_NONAME == -2, "EAI errors");

static void numeric(void) {
  for (int iteration = 0; iteration < 80; ++iteration) {
    struct addrinfo hints = {0}, *list = NULL;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_CANONNAME;
    hints.ai_family = AF_INET;
    CHECK(getaddrinfo("192.0.2.73", "65535", &hints, &list) == 0);
    CHECK(list && list->ai_next && !list->ai_next->ai_next);
    CHECK(list->ai_family == AF_INET && list->ai_addrlen == 16);
    CHECK(list->ai_socktype == SOCK_STREAM && list->ai_protocol == IPPROTO_TCP);
    CHECK(list->ai_next->ai_socktype == SOCK_DGRAM);
    CHECK(list->ai_canonname && !strcmp(list->ai_canonname, "192.0.2.73"));
    char host[NI_MAXHOST], service[NI_MAXSERV];
    CHECK(getnameinfo(list->ai_addr, list->ai_addrlen, host, sizeof(host),
                      service, sizeof(service),
                      NI_NUMERICHOST | NI_NUMERICSERV) == 0);
    CHECK(!strcmp(host, "192.0.2.73") && !strcmp(service, "65535"));
    struct addrinfo *tail = list->ai_next;
    list->ai_next = NULL;
    freeaddrinfo(list);
    freeaddrinfo(tail);
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    CHECK(getaddrinfo("fe80::1%lo", "73", &hints, &list) == 0);
    CHECK(list && !list->ai_next && list->ai_addrlen == 28);
    CHECK(((struct sockaddr_in6 *)list->ai_addr)->sin6_scope_id == 1);
    freeaddrinfo(list);
  }
  struct addrinfo *result = (void *)1;
  errno = 0;
  CHECK(getaddrinfo((const char *)1, "73", NULL, &result) == EAI_SYSTEM);
  CHECK(errno == EFAULT && result == NULL);
  CHECK(strlen(gai_strerror(EAI_AGAIN)) > 0);
  CHECK(strlen(gai_strerror(123456)) > 0);
  freeaddrinfo(NULL);
  puts("netdb-c: PASS public ABI, numeric v4/v6, interface scope, C list "
       "lifetime and EFAULT");
}

static void write_file(const char *path, const char *text) {
  FILE *file = fopen(path, "w");
  CHECK(file != NULL);
  CHECK(fwrite(text, 1, strlen(text), file) == strlen(text));
  CHECK(fclose(file) == 0);
  CHECK(chmod(path, 0644) == 0);
}
static void local_case(int denied) {
  struct addrinfo hints = {0}, *list = NULL;
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_CANONNAME;
  int code = getaddrinfo("fixture-alias", "fixture-service", &hints, &list);
  if (denied) {
    CHECK(code == EAI_SYSTEM && errno == EACCES && list == NULL);
    puts("netdb-c: PASS inaccessible services file does not bypass POSIX "
         "credentials");
    return;
  }
  CHECK(code == 0);
  int count = 0;
  for (struct addrinfo *entry = list; entry; entry = entry->ai_next) {
    char host[NI_MAXHOST], service[NI_MAXSERV];
    CHECK(getnameinfo(entry->ai_addr, entry->ai_addrlen, host, sizeof(host),
                      service, sizeof(service),
                      NI_NUMERICHOST | NI_NUMERICSERV) == 0);
    CHECK(!strcmp(host, count < 2 ? "192.0.2.8" : "192.0.2.9"));
    CHECK(!strcmp(service, count % 2 == 0 ? "43000" : "43001"));
    if (count == 0)
      CHECK(!strcmp(entry->ai_canonname, "fixture.example"));
    else
      CHECK(entry->ai_canonname == NULL);
    ++count;
  }
  CHECK(count == 4);
  char host[NI_MAXHOST], service[NI_MAXSERV];
  CHECK(getnameinfo(list->ai_addr, list->ai_addrlen, host, sizeof(host),
                    service, sizeof(service), NI_NOFQDN) == 0);
  CHECK(!strcmp(host, "fixture.example") && !strcmp(service, "fixture-stream"));
  freeaddrinfo(list);
  printf("netdb-c: PASS caller-root hosts/services, aliases, protocol-specific "
         "ports and reverse names euid %u\n",
         (unsigned)geteuid());
}
static void namespaces(void) {
  char root[] = "/tmp/netdb-XXXXXX";
  CHECK(mkdtemp(root) == root);
  CHECK(chmod(root, 0755) == 0);
  char etc[128], hosts[128], services[128];
  snprintf(etc, sizeof(etc), "%s/etc", root);
  snprintf(hosts, sizeof(hosts), "%s/hosts", etc);
  snprintf(services, sizeof(services), "%s/services", etc);
  CHECK(mkdir(etc, 0755) == 0);
  write_file(hosts, "192.0.2.8 fixture.example fixture-alias\n192.0.2.9 "
                    "second.example fixture-alias\n");
  write_file(services,
             "fixture-stream 43000/tcp fixture-service\nfixture-dgram "
             "43001/udp fixture-service\n");
  for (int i = 0; i < 3; ++i) {
    if (i == 2)
      CHECK(chmod(services, 0600) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
      CHECK(chroot(root) == 0 && chdir("/") == 0);
      CHECK(seteuid(i == 0 ? 0 : 501) == 0);
      local_case(i == 2);
      fflush(NULL);
      _exit(0);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child && status == 0);
  }
  CHECK(unlink(hosts) == 0 && unlink(services) == 0);
  CHECK(rmdir(etc) == 0 && rmdir(root) == 0);
}
static void unavailable_dns(void) {
  struct addrinfo hints = {0}, *list = NULL;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  errno = 0;
  /* The checked runner has no NIC. An actual job must report this failure,
   * never a fabricated address or successful empty result. */
  CHECK(getaddrinfo("netdb-probe.invalid", "73", &hints, &list) == EAI_SYSTEM);
  CHECK(errno == ENXIO && list == NULL);
  printf("netdb-c: PASS actual no-NIC DNS job failure euid %u\n",
         (unsigned)geteuid());
}
int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  numeric();
  if (geteuid() == 0)
    namespaces();
  unavailable_dns();
  puts("netdb-c: PASS");
  return 0;
}
