/*************************************************************************************************
 * The utility API of Tokyo Tyrant
 *                                                               Copyright (C) 2006-2010 FAL Labs
 * This file is part of Tokyo Tyrant.
 * Tokyo Tyrant is free software; you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation; either
 * version 2.1 of the License or any later version.  Tokyo Tyrant is distributed in the hope
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * You should have received a copy of the GNU Lesser General Public License along with Tokyo
 * Tyrant; if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307 USA.
 *************************************************************************************************/


#include "ttutil.h"
#include "myconf.h"
#include <netinet/in.h>

// add by steven start
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
// add by steven end

/*************************************************************************************************
 * basic utilities
 *************************************************************************************************/


#define SOCKPATHBUFSIZ 108               // size of a socket path buffer
#define SOCKRCVTIMEO   0.25              // timeout of the recv call of socket
#define SOCKSNDTIMEO   0.25              // timeout of the send call of socket
#define SOCKCNCTTIMEO  5.0               // timeout of the connect call of socket
#define SOCKLINEBUFSIZ 4096              // size of a line buffer of socket
#define SOCKLINEMAXSIZ (16*1024*1024)    // maximum size of a line of socket
#define HTTPBODYMAXSIZ (256*1024*1024)   // maximum size of the entity body of HTTP
#define TRILLIONNUM    1000000000000     // trillion number

/**
 * access control list. add by steven.zhoulin@2023-08-22
 */
// add by steven start
struct acl_node ACL_NODES[10000];
int ACL_NODES_TAIL = 0;
int ACL_ENABLE = 0;
typedef long ipv6addr[2];

static char *trim(char *line);
static int expand(const char *input, char *output);
static struct acl_node parse_acl_node(char *line);

static int  parse_mask_ipv4(int mask);
static long parse_mask_ipv6(long mask);

static long parse_address_ipv4(char *ip);
static void parse_address_ipv6(char *ip, ipv6addr addr);

static bool acl_check_ipv4(char *ip);
static bool acl_check_ipv6(char *ip);

static void display(struct acl_node aclNode);
static void assertTrue(char *addr);
// add by steven end


/* String containing the version information. */
const char *ttversion = _TT_VERSION;

// add by steven start
void init_acl_list(char *acl_file) {
    printf("Access control file: %s\n", acl_file);
    printf("-----------------------------------------------------------\n");
    FILE *file;
    char line[1025];

    if (NULL == (file = fopen(acl_file, "r"))) {
        printf("fopen error!\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, sizeof line, file)) {
        char *p = trim(line);
        if (NULL != p) {
            struct acl_node aclNode = parse_acl_node(p);
            ACL_NODES[ACL_NODES_TAIL++] = aclNode;
        }
    }

    fclose(file);
    printf("-----------------------------------------------------------\n");
}

bool acl_check(char *ip) {
    char *pos = strstr(ip, ":");
    if (NULL == pos) {
        return acl_check_ipv4(ip);
    } else {
        return acl_check_ipv6(ip);
    }
}

static void assertTrue(char *addr) {
    if (acl_check(addr)) {
        fprintf(stdout, "[ true] %s\n", addr);
    } else {
        fprintf(stderr, "[false] %s\n", addr);
    }
}

static long parse_mask_ipv6(long mask) {
    long rtn = 0;
    long i;
    for (i = 63; i >= (64 - mask); i--) {
        rtn += (0x1l << i);
    }
    return rtn;
}

static int parse_mask_ipv4(int mask) {
    int rtn = 0;
    int i;
    for (i = 31; i >= (32 - mask); i--) {
        rtn += (0x1 << i);
    }
    return rtn;
}

static void display(struct acl_node aclNode) {
    if (aclNode.ipv6) {
        printf("ipv6 rule: ");
        int i;
        for (i = 63; i >= 0; i--) {
            printf("%c", (aclNode.high & 0x01l << i) ? '1' : '0');
            if (i % 16 == 0) printf(" ");
        }

        int k;
        for (k = 63; k >= 0; k--) {
            printf("%c", (aclNode.low & 0x01l << k) ? '1' : '0');
            if (k % 16 == 0) printf(" ");
        }
        printf(" mask_len: %ld", aclNode.high_len + aclNode.low_len);
    } else {
        printf("ipv4 rule: ");
        int i;
        for (i = 31; i >= 0; i--) {
            printf("%c", (aclNode.low & 0x01 << i) ? '1' : '0');
            if (i % 8 == 0) printf(" ");
        }
        printf(" mask_len: %ld", aclNode.low_len);
    }
    printf("\n");
}

static long parse_address_ipv4(char *ip) {
    char buff[INET_ADDRSTRLEN];
    long rtn = 0;
    strcpy(buff, ip);
    char *result = strtok(buff, ".");
    while (NULL != result) {
        int i = atoi(result);
        rtn = (rtn << 8) + i;
        result = strtok(NULL, ".");
    }
    return rtn;
}

static void parse_address_ipv6(char *ip, ipv6addr addr) {
    char buff[INET6_ADDRSTRLEN];
    expand(ip, buff);
    char *result = strtok(buff, ":");
    int count = 0;
    while (NULL != result && count < 4) {
        count++;
        unsigned int i = 0;
        sscanf(result, "%x", &i);
        addr[0] = (addr[0] << 16) + i;
        result = strtok(NULL, ":");
    }

    while (NULL != result) {
        unsigned int i = 0;
        sscanf(result, "%x", &i);
        addr[1] = (addr[1] << 16) + i;
        result = strtok(NULL, ":");
    }
}

static bool acl_check_ipv4(char *ip) {
    long addr = parse_address_ipv4(ip);

    int i;
    for (i = 0; i < ACL_NODES_TAIL; i++) {
        if (ACL_NODES[i].ipv6) {
            continue;
        }
        int k;
        int len = 32 - ACL_NODES[i].low_len;
        for (k = 31; k >= len; k--) {
            if (((0x1 << k) & ACL_NODES[i].low) != ((0x1 << k) & addr)) {
                break;
            }
        }

        if (k == (len - 1)) {
            return true;
        }
    }

    return false;
}

static bool acl_check_ipv6(char *ip) {
    ipv6addr addr = {0l, 0l};
    parse_address_ipv6(ip, addr);
    int i;
    for (i = 0; i < ACL_NODES_TAIL; i++) {
        if (!ACL_NODES[i].ipv6) {
            continue;
        }
        long high_k = 63;
        long low_k = 63;
        long high_len = 64 - ACL_NODES[i].high_len;
        long low_len = 64 - ACL_NODES[i].low_len;

        while (high_k >= high_len) {
            if (((0x1l << high_k) & ACL_NODES[i].high) != ((0x1l << high_k) & addr[0])) {
                break;
            }
            high_k--;
        }

        while (low_k >= low_len) {
            if (((0x1l << low_k) & ACL_NODES[i].low) != ((0x1l << low_k) & addr[1])) {
                break;
            }
            low_k--;
        }

        if (high_k == (high_len - 1) && low_k == (low_len - 1)) {
            return true;
        }
    }

    return false;
}

static struct acl_node parse_acl_node_ipv4(char *line) {
    char *addr = strtok(line, "/");
    char *mask = strtok(NULL, "/");

    if (NULL == mask) {
        mask = "32";
    }

    long net = 0;
    char *p = strtok(addr, ".");
    while (NULL != p) {
        net = (net << 8) + atoi(p);
        p = strtok(NULL, ".");
    }

    int maskLen = atoi(mask);
    net = net & parse_mask_ipv4(maskLen);

    struct acl_node aclNode;
    aclNode.ipv6 = false;
    aclNode.low = net;
    aclNode.low_len = atoi(mask);

    display(aclNode);
    return aclNode;
}

static struct acl_node parse_acl_node_ipv6(char *line) {
    char *addr = strtok(line, "/");
    char *mask = strtok(NULL, "/");
    if (NULL == mask) {
        mask = "128";
    }
    long high = 0;
    long low = 0;
    char expand_addr[INET6_ADDRSTRLEN];

    expand(addr, expand_addr);
    char *p = strtok(expand_addr, ":");

    int count = 0;
    while (NULL != p && count < 4) {
        count++;
        unsigned int i = 0;
        sscanf(p, "%x", &i);
        high = (high << 16) + i;
        p = strtok(NULL, ":");
    }

    while (NULL != p) {
        unsigned int i = 0;
        sscanf(p, "%x", &i);
        low = (low << 16) + i;
        p = strtok(NULL, ":");
    }

    struct acl_node aclNode;
    long len = atoi(mask);

    aclNode.ipv6 = true;
    aclNode.high_len = (64 - len) <= 0 ? 64 : 64 - len;
    aclNode.low_len  = (len - 64) <= 0 ?  0 : len - 64;
    aclNode.high = high & parse_mask_ipv6(aclNode.high_len);
    aclNode.low  =  low & parse_mask_ipv6(aclNode.low_len);

    display(aclNode);
    return aclNode;
}

static struct acl_node parse_acl_node(char *line) {
    char *pos = strstr(line, ":");
    if (NULL == pos) {
        return parse_acl_node_ipv4(line);
    } else {
        return parse_acl_node_ipv6(line);
    }
}

static char *trim(char *line) {
    char *start = line;
    char *end = start + strlen(line) - 1;
    while (*start && isspace(*start)) start++;
    while (end > start && isspace(*end)) *end-- = '\0';
    line[strcspn(line, "\n")] = '\0';
    if (strlen(start)) {
        if (start[0] == '#') {
            return NULL;
        }
        return start;
    }
    return NULL;
}

static int expand(const char *input, char *output) {
    struct in6_addr ipv6_addr;

    // 将IPv6地址转换为二进制格式
    if (inet_pton(AF_INET6, input, &ipv6_addr) <= 0) {
        printf("Error ipv6 addr: %s\n", input);
        return -1;
    }

    // 将IPv6地址展开为字符串
    char expanded_ipv6_str[INET6_ADDRSTRLEN];
    memset(expanded_ipv6_str, 0, sizeof(expanded_ipv6_str));
    sprintf(expanded_ipv6_str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            ntohs(ipv6_addr.s6_addr[0])  >> 8, ntohs(ipv6_addr.s6_addr[1])  >> 8,
            ntohs(ipv6_addr.s6_addr[2])  >> 8, ntohs(ipv6_addr.s6_addr[3])  >> 8,
            ntohs(ipv6_addr.s6_addr[4])  >> 8, ntohs(ipv6_addr.s6_addr[5])  >> 8,
            ntohs(ipv6_addr.s6_addr[6])  >> 8, ntohs(ipv6_addr.s6_addr[7])  >> 8,
            ntohs(ipv6_addr.s6_addr[8])  >> 8, ntohs(ipv6_addr.s6_addr[9])  >> 8,
            ntohs(ipv6_addr.s6_addr[10]) >> 8, ntohs(ipv6_addr.s6_addr[11]) >> 8,
            ntohs(ipv6_addr.s6_addr[12]) >> 8, ntohs(ipv6_addr.s6_addr[13]) >> 8,
            ntohs(ipv6_addr.s6_addr[14]) >> 8, ntohs(ipv6_addr.s6_addr[15]) >> 8);

    // 将展开后的IPv6地址拷贝到输出缓冲区
    strcpy(output, expanded_ipv6_str);
    return 0;
}
// add by steven end


/* Get the primary name of the local host. */
bool ttgetlocalhostname(char *name){
  assert(name);
  if(gethostname(name, TTADDRBUFSIZ - 1) != 0){
    sprintf(name, "localhost");
    return false;
  }
  return true;
}


/* Get the address of a host. */
bool ttgethostaddr(const char *name, char *addr){
  assert(name && addr);
  struct addrinfo hints, *result;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = 0;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;
  if(getaddrinfo(name, NULL, &hints, &result) != 0){
    *addr = '\0';
    return false;
  }
  if(!result){
    freeaddrinfo(result);
    return false;
  }
  if(result->ai_addr->sa_family != AF_INET){
    freeaddrinfo(result);
    return false;
  }
  if(getnameinfo(result->ai_addr, result->ai_addrlen,
                 addr, TTADDRBUFSIZ, NULL, 0, NI_NUMERICHOST) != 0){
    freeaddrinfo(result);
    return false;
  }
  freeaddrinfo(result);
  return true;
}


/* Open a client socket of TCP/IP stream to a server. */
int ttopensock(const char *addr, int port){
  assert(addr && port >= 0);
  struct sockaddr_in6 sain;
  memset(&sain, 0, sizeof(sain));
  sain.sin6_family = AF_INET6;
  sain.sin6_addr = in6addr_any;
  //if(inet_aton(addr, &sain.sin6_addr) == 0) return -1;
  uint16_t snum = port;
  sain.sin6_port = htons(snum);
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  if(fd == -1) return -1;
  int optint = 1;
  setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&optint, sizeof(optint));
  struct timeval opttv;
  opttv.tv_sec = (int)SOCKRCVTIMEO;
  opttv.tv_usec = (SOCKRCVTIMEO - (int)SOCKRCVTIMEO) * 1000000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&opttv, sizeof(opttv));
  opttv.tv_sec = (int)SOCKSNDTIMEO;
  opttv.tv_usec = (SOCKSNDTIMEO - (int)SOCKSNDTIMEO) * 1000000;
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&opttv, sizeof(opttv));
  optint = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&optint, sizeof(optint));
  double dl = tctime() + SOCKCNCTTIMEO;
  do {
    int ocs = PTHREAD_CANCEL_DISABLE;
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &ocs);
    int rv = connect(fd, (struct sockaddr *)&sain, sizeof(sain));
    int en = errno;
    pthread_setcancelstate(ocs, NULL);
    if(rv == 0) return fd;
    if(en != EINTR && en != EAGAIN && en != EINPROGRESS && en != EALREADY && en != ETIMEDOUT)
      break;
  } while(tctime() <= dl);
  close(fd);
  return -1;
}


/* Open a client socket of UNIX domain stream to a server. */
int ttopensockunix(const char *path){
  assert(path);
  struct sockaddr_un saun;
  memset(&saun, 0, sizeof(saun));
  saun.sun_family = AF_UNIX;
  snprintf(saun.sun_path, SOCKPATHBUFSIZ, "%s", path);
  int fd = socket(PF_UNIX, SOCK_STREAM, 0);
  if(fd == -1) return -1;
  int optint = 1;
  setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&optint, sizeof(optint));
  struct timeval opttv;
  opttv.tv_sec = (int)SOCKRCVTIMEO;
  opttv.tv_usec = (SOCKRCVTIMEO - (int)SOCKRCVTIMEO) * 1000000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&opttv, sizeof(opttv));
  opttv.tv_sec = (int)SOCKSNDTIMEO;
  opttv.tv_usec = (SOCKSNDTIMEO - (int)SOCKSNDTIMEO) * 1000000;
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&opttv, sizeof(opttv));
  double dl = tctime() + SOCKCNCTTIMEO;
  do {
    int ocs = PTHREAD_CANCEL_DISABLE;
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &ocs);
    int rv = connect(fd, (struct sockaddr *)&saun, sizeof(saun));
    int en = errno;
    pthread_setcancelstate(ocs, NULL);
    if(rv == 0) return fd;
    if(en != EINTR && en != EAGAIN && en != EINPROGRESS && en != EALREADY && en != ETIMEDOUT)
      break;
  } while(tctime() <= dl);
  close(fd);
  return -1;
}


/* Open a server socket of TCP/IP stream to clients. */
int ttopenservsock(const char *addr, int port){
  assert(port >= 0);
  struct sockaddr_in6 sain;
  memset(&sain, 0, sizeof(sain));
  sain.sin6_family = AF_INET6;
  sain.sin6_addr = in6addr_any;
  //if(inet_aton(addr ? addr : "0.0.0.0", &sain.sin6_addr) == 0) return -1;
  uint16_t snum = port;
  sain.sin6_port = htons(snum);
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  if(fd == -1) return -1;
  int optint = 1;
  if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optint, sizeof(optint)) != 0){
    close(fd);
    return -1;
  }
  if(bind(fd, (struct sockaddr *)&sain, sizeof(sain)) != 0 ||
     listen(fd, SOMAXCONN) != 0){
    close(fd);
    return -1;
  }
  return fd;
}


/* Open a server socket of UNIX domain stream to clients. */
int ttopenservsockunix(const char *path){
  assert(path);
  if(*path == '\0') return -1;
  struct sockaddr_un saun;
  memset(&saun, 0, sizeof(saun));
  saun.sun_family = AF_UNIX;
  snprintf(saun.sun_path, SOCKPATHBUFSIZ, "%s", path);
  int fd = socket(PF_UNIX, SOCK_STREAM, 0);
  if(fd == -1) return -1;
  if(bind(fd, (struct sockaddr *)&saun, sizeof(saun)) != 0 ||
     listen(fd, SOMAXCONN) != 0){
    close(fd);
    return -1;
  }
  return fd;
}


/* Accept a TCP/IP connection from a client. */
int ttacceptsock(TTSERV *serv, int fd, char *addr, int *pp){
  assert(fd >= 0);
  do {
    struct sockaddr_in6 sain;
    memset(&sain, 0, sizeof(sain));
    sain.sin6_family = AF_INET6;
    socklen_t slen = sizeof(sain);
    int cfd = accept(fd, (struct sockaddr *)&sain, &slen);

    // add by steven@2020-09-12
    struct sockaddr_in6 clientaddr;
    memset(&clientaddr, 0x00, sizeof(clientaddr));
    socklen_t nl = sizeof(clientaddr);
    int ret = getpeername(cfd, (struct sockaddr*)&clientaddr, &nl);
    if (ret == 0) {
        char peerip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6,
                    &clientaddr.sin6_addr,
                    peerip,
                    sizeof(peerip));
        if (ACL_ENABLE && !acl_check(peerip)) {
            time_t timep;
            time(&timep);
            close(cfd);
            ttservlog(serv, TTLOGSYSTEM, "deny illegal access from %s", peerip);
            //return -1;
        }
    } else {
        perror("getpeername");
        memset(&clientaddr, 0, sizeof(clientaddr));
    }

    if(cfd >= 0){
      int optint = 1;
      setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&optint, sizeof(optint));
      struct timeval opttv;
      opttv.tv_sec = (int)SOCKRCVTIMEO;
      opttv.tv_usec = (SOCKRCVTIMEO - (int)SOCKRCVTIMEO) * 1000000;
      setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&opttv, sizeof(opttv));
      opttv.tv_sec = (int)SOCKSNDTIMEO;
      opttv.tv_usec = (SOCKSNDTIMEO - (int)SOCKSNDTIMEO) * 1000000;
      setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&opttv, sizeof(opttv));
      optint = 1;
      setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (char *)&optint, sizeof(optint));
      if(addr){
        if(getnameinfo((struct sockaddr *)&sain, sizeof(sain), addr, TTADDRBUFSIZ,
                       NULL, 0, NI_NUMERICHOST) != 0) sprintf(addr, "0.0.0.0");
      }
      if(pp) *pp = (int)ntohs(sain.sin6_port);
      return cfd;
    }
  } while(errno == EINTR || errno == EAGAIN);
  return -1;
}


/* Accept a UNIX domain connection from a client. */
int ttacceptsockunix(int fd){
  assert(fd >= 0);
  do {
    int cfd = accept(fd, NULL, NULL);
    if(cfd >= 0){
      int optint = 1;
      setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&optint, sizeof(optint));
      struct timeval opttv;
      opttv.tv_sec = (int)SOCKRCVTIMEO;
      opttv.tv_usec = (SOCKRCVTIMEO - (int)SOCKRCVTIMEO) * 1000000;
      setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&opttv, sizeof(opttv));
      opttv.tv_sec = (int)SOCKSNDTIMEO;
      opttv.tv_usec = (SOCKSNDTIMEO - (int)SOCKSNDTIMEO) * 1000000;
      setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&opttv, sizeof(opttv));
      return cfd;
    }
  } while(errno == EINTR || errno == EAGAIN);
  return -1;
}


/* Shutdown and close a socket. */
bool ttclosesock(int fd){
  assert(fd >= 0);
  bool err = false;
  if(shutdown(fd, 2) != 0 && errno != ENOTCONN && errno != ECONNRESET) err = true;
  if(close(fd) != 0 && errno != ENOTCONN && errno != ECONNRESET) err = true;
  return !err;
}


/* Wait an I/O event of a socket. */
bool ttwaitsock(int fd, int mode, double timeout){
  assert(fd >= 0 && mode >= 0 && timeout >= 0);
  while(true){
    fd_set set;
    FD_ZERO(&set);
    FD_SET(fd, &set);
    double integ, fract;
    fract = modf(timeout, &integ);
    struct timespec ts;
    ts.tv_sec = integ;
    ts.tv_nsec = fract * 1000000000.0;
    int rv = -1;
    switch(mode){
      case 0:
        rv = pselect(fd + 1, &set, NULL, NULL, &ts, NULL);
        break;
      case 1:
        rv = pselect(fd + 1, NULL, &set, NULL, &ts, NULL);
        break;
      case 2:
        rv = pselect(fd + 1, NULL, NULL, &set, &ts, NULL);
        break;
    }
    if(rv > 0) return true;
    if(rv == 0 || errno != EINVAL) break;
  }
  return false;
}


/* Create a socket object. */
TTSOCK *ttsocknew(int fd){
  assert(fd >= 0);
  TTSOCK *sock = tcmalloc(sizeof(*sock));
  sock->fd = fd;
  sock->rp = sock->buf;
  sock->ep = sock->buf;
  sock->end = false;
  sock->to = 0.0;
  sock->dl = HUGE_VAL;
  return sock;
}


/* Delete a socket object. */
void ttsockdel(TTSOCK *sock){
  assert(sock);
  tcfree(sock);
}


/* Set the lifetime of a socket object. */
void ttsocksetlife(TTSOCK *sock, double lifetime){
  assert(sock && lifetime >= 0);
  sock->to = lifetime >= INT_MAX ? 0.0 : lifetime;
  sock->dl = tctime() + lifetime;
}


/* Send data by a socket. */
bool ttsocksend(TTSOCK *sock, const void *buf, int size){
  assert(sock && buf && size >= 0);
  const char *rp = buf;
  do {
    int ocs = PTHREAD_CANCEL_DISABLE;
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &ocs);
    if(sock->to > 0.0 && !ttwaitsock(sock->fd, 1, sock->to)){
      pthread_setcancelstate(ocs, NULL);
      return false;
    }
    int wb = send(sock->fd, rp, size, 0);
    int en = errno;
    pthread_setcancelstate(ocs, NULL);
    switch(wb){
      case -1:
        if(en != EINTR && en != EAGAIN && en != EWOULDBLOCK){
          sock->end = true;
          return false;
        }
        if(tctime() > sock->dl){
          sock->end = true;
          return false;
        }
        break;
      case 0:
        break;
      default:
        rp += wb;
        size -= wb;
        break;
    }
  } while(size > 0);
  return true;
}


/* Send formatted data by a socket. */
bool ttsockprintf(TTSOCK *sock, const char *format, ...){
  assert(sock && format);
  bool err = false;
  TCXSTR *xstr = tcxstrnew();
  pthread_cleanup_push((void (*)(void *))tcxstrdel, xstr);
  va_list ap;
  va_start(ap, format);
  while(*format != '\0'){
    if(*format == '%'){
      char cbuf[TTNUMBUFSIZ];
      cbuf[0] = '%';
      int cblen = 1;
      int lnum = 0;
      format++;
      while(strchr("0123456789 .+-hlLz", *format) && *format != '\0' &&
            cblen < TTNUMBUFSIZ - 1){
        if(*format == 'l' || *format == 'L') lnum++;
        cbuf[cblen++] = *(format++);
      }
      cbuf[cblen++] = *format;
      cbuf[cblen] = '\0';
      int tlen;
      char *tmp, tbuf[TTNUMBUFSIZ*2];
      switch(*format){
        case 's':
          tmp = va_arg(ap, char *);
          if(!tmp) tmp = "(null)";
          tcxstrcat2(xstr, tmp);
          break;
        case 'd':
          if(lnum >= 2){
            tlen = sprintf(tbuf, cbuf, va_arg(ap, long long));
          } else if(lnum >= 1){
            tlen = sprintf(tbuf, cbuf, va_arg(ap, long));
          } else {
            tlen = sprintf(tbuf, cbuf, va_arg(ap, int));
          }
          tcxstrcat(xstr, tbuf, tlen);
          break;
        case 'o': case 'u': case 'x': case 'X': case 'c':
          if(lnum >= 2){
            tlen = sprintf(tbuf, cbuf, va_arg(ap, unsigned long long));
          } else if(lnum >= 1){
            tlen = sprintf(tbuf, cbuf, va_arg(ap, unsigned long));
          } else {
            tlen = sprintf(tbuf, cbuf, va_arg(ap, unsigned int));
          }
          tcxstrcat(xstr, tbuf, tlen);
          break;
        case 'e': case 'E': case 'f': case 'g': case 'G':
          if(lnum >= 1){
            tlen = sprintf(tbuf, cbuf, va_arg(ap, long double));
          } else {
            tlen = sprintf(tbuf, cbuf, va_arg(ap, double));
          }
          tcxstrcat(xstr, tbuf, tlen);
          break;
        case '@':
          tmp = va_arg(ap, char *);
          if(!tmp) tmp = "(null)";
          while(*tmp){
            switch(*tmp){
              case '&': tcxstrcat(xstr, "&amp;", 5); break;
              case '<': tcxstrcat(xstr, "&lt;", 4); break;
              case '>': tcxstrcat(xstr, "&gt;", 4); break;
              case '"': tcxstrcat(xstr, "&quot;", 6); break;
              default:
                if(!((*tmp >= 0 && *tmp <= 0x8) || (*tmp >= 0x0e && *tmp <= 0x1f)))
                  tcxstrcat(xstr, tmp, 1);
                break;
            }
            tmp++;
          }
          break;
        case '?':
          tmp = va_arg(ap, char *);
          if(!tmp) tmp = "(null)";
          while(*tmp){
            unsigned char c = *(unsigned char *)tmp;
            if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || (c != '\0' && strchr("_-.", c))){
              tcxstrcat(xstr, tmp, 1);
            } else {
              tlen = sprintf(tbuf, "%%%02X", c);
              tcxstrcat(xstr, tbuf, tlen);
            }
            tmp++;
          }
          break;
        case '%':
          tcxstrcat(xstr, "%", 1);
          break;
      }
    } else {
      tcxstrcat(xstr, format, 1);
    }
    format++;
  }
  va_end(ap);
  if(!ttsocksend(sock, tcxstrptr(xstr), tcxstrsize(xstr))) err = true;
  pthread_cleanup_pop(1);
  return !err;
}


/* Receive data by a socket. */
bool ttsockrecv(TTSOCK *sock, char *buf, int size){
  assert(sock && buf && size >= 0);
  if(sock->rp + size <= sock->ep){
    memcpy(buf, sock->rp, size);
    sock->rp += size;
    return true;
  }
  bool err = false;
  char *wp = buf;
  while(size > 0){
    int c = ttsockgetc(sock);
    if(c == -1){
      err = true;
      break;
    }
    *(wp++) = c;
    size--;
  }
  return !err;
}


/* Receive one byte by a socket. */
int ttsockgetc(TTSOCK *sock){
  assert(sock);
  if(sock->rp < sock->ep) return *(unsigned char *)(sock->rp++);
  int en;
  do {
    int ocs = PTHREAD_CANCEL_DISABLE;
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &ocs);
    if(sock->to > 0.0 && !ttwaitsock(sock->fd, 0, sock->to)){
      pthread_setcancelstate(ocs, NULL);
      return -1;
    }
    int rv = recv(sock->fd, sock->buf, TTIOBUFSIZ, 0);
    en = errno;
    pthread_setcancelstate(ocs, NULL);
    if(rv > 0){
      sock->rp = sock->buf + 1;
      sock->ep = sock->buf + rv;
      return *(unsigned char *)sock->buf;
    } else if(rv == 0){
      sock->end = true;
      return -1;
    }
  } while((en == EINTR || en == EAGAIN || en == EWOULDBLOCK) && tctime() <= sock->dl);
  sock->end = true;
  return -1;
}


/* Push a character back to a socket. */
void ttsockungetc(TTSOCK *sock, int c){
  assert(sock);
  if(sock->rp <= sock->buf) return;
  sock->rp--;
  *(unsigned char *)sock->rp = c;
}


/* Receive one line by a socket. */
bool ttsockgets(TTSOCK *sock, char *buf, int size){
  assert(sock && buf && size > 0);
  bool err = false;
  size--;
  char *wp = buf;
  while(size > 0){
    int c = ttsockgetc(sock);
    if(c == '\n') break;
    if(c == -1){
      err = true;
      break;
    }
    if(c != '\r'){
      *(wp++) = c;
      size--;
    }
  }
  *wp = '\0';
  return !err;
}


/* Receive one line by a socket into allocated buffer. */
char *ttsockgets2(TTSOCK *sock){
  assert(sock);
  bool err = false;
  TCXSTR *xstr = tcxstrnew3(SOCKLINEBUFSIZ);
  pthread_cleanup_push((void (*)(void *))tcxstrdel, xstr);
  int size = 0;
  while(true){
    int c = ttsockgetc(sock);
    if(c == '\n') break;
    if(c == -1){
      err = true;
      break;
    }
    if(c != '\r'){
      unsigned char b = c;
      tcxstrcat(xstr, &b, sizeof(b));
      size++;
      if(size >= SOCKLINEMAXSIZ){
        err = true;
        break;
      }
    }
  }
  pthread_cleanup_pop(0);
  return tcxstrtomalloc(xstr);
}


/* Receive an 32-bit integer by a socket. */
uint32_t ttsockgetint32(TTSOCK *sock){
  assert(sock);
  uint32_t num;
  ttsockrecv(sock, (char *)&num, sizeof(num));
  return TTNTOHL(num);
}


/* Receive an 64-bit integer by a socket. */
uint64_t ttsockgetint64(TTSOCK *sock){
  assert(sock);
  uint64_t num;
  ttsockrecv(sock, (char *)&num, sizeof(num));
  return TTNTOHLL(num);
}


/* Check whehter a socket is end. */
bool ttsockcheckend(TTSOCK *sock){
  assert(sock);
  return sock->end;
}


/* Check the size of prefetched data in a socket. */
int ttsockcheckpfsiz(TTSOCK *sock){
  assert(sock);
  if(sock->end) return 0;
  return sock->ep - sock->rp;
}


/* Fetch the resource of a URL by HTTP. */
int tthttpfetch(const char *url, TCMAP *reqheads, TCMAP *resheads, TCXSTR *resbody){
  assert(url);
  int code = -1;
  TCMAP *elems = tcurlbreak(url);
  pthread_cleanup_push((void (*)(void *))tcmapdel, elems);
  const char *scheme = tcmapget2(elems, "scheme");
  const char *host = tcmapget2(elems, "host");
  const char *port = tcmapget2(elems, "port");
  const char *authority = tcmapget2(elems, "authority");
  const char *path = tcmapget2(elems, "path");
  const char *query = tcmapget2(elems, "query");
  if(scheme && !tcstricmp(scheme, "http") && host){
    if(*host == '\0') host = "127.0.0.1";
    int pnum = port ? tcatoi(port) : 80;
    if(pnum < 1) pnum = 80;
    if(!path) path = "/";
    char addr[TTADDRBUFSIZ];
    int fd;
    if(ttgethostaddr(host, addr) && (fd = ttopensock(addr, pnum)) != -1){
      pthread_cleanup_push((void (*)(void *))ttclosesock, (void *)(intptr_t)fd);
      TTSOCK *sock = ttsocknew(fd);
      pthread_cleanup_push((void (*)(void *))ttsockdel, sock);
      TCXSTR *obuf = tcxstrnew();
      pthread_cleanup_push((void (*)(void *))tcxstrdel, obuf);
      if(query){
        tcxstrprintf(obuf, "GET %s?%s HTTP/1.1\r\n", path, query);
      } else {
        tcxstrprintf(obuf, "GET %s HTTP/1.1\r\n", path);
      }
      if(pnum == 80){
        tcxstrprintf(obuf, "Host: %s\r\n", host);
      } else {
        tcxstrprintf(obuf, "Host: %s:%d\r\n", host, pnum);
      }
      tcxstrprintf(obuf, "Connection: close\r\n", host, port);
      if(authority){
        char *enc = tcbaseencode(authority, strlen(authority));
        tcxstrprintf(obuf, "Authorization: Basic %s\r\n", enc);
        tcfree(enc);
      }
      double tout = -1;
      if(reqheads){
        tcmapiterinit(reqheads);
        const char *name;
        while((name = tcmapiternext2(reqheads)) != NULL){
          if(strchr(name, ':') || !tcstricmp(name, "connection")) continue;
          if(!tcstricmp(name, "x-tt-timeout")){
            tout = tcatof(tcmapget2(reqheads, name));
          } else {
            char *cap = tcstrdup(name);
            tcstrtolower(cap);
            char *wp = cap;
            bool head = true;
            while(*wp != '\0'){
              if(head && *wp >= 'a' && *wp <= 'z') *wp -= 'a' - 'A';
              head = *wp == '-' || *wp == ' ';
              wp++;
            }
            tcxstrprintf(obuf, "%s: %s\r\n", cap, tcmapget2(reqheads, name));
            tcfree(cap);
          }
        }
      }
      tcxstrprintf(obuf, "\r\n", host);
      if(tout > 0) ttsocksetlife(sock, tout);
      if(ttsocksend(sock, tcxstrptr(obuf), tcxstrsize(obuf))){
        char line[SOCKLINEBUFSIZ];
        if(ttsockgets(sock, line, SOCKLINEBUFSIZ) && tcstrfwm(line, "HTTP/")){
          tcstrsqzspc(line);
          const char *rp = strchr(line, ' ');
          code = tcatoi(rp + 1);
          if(resheads) tcmapput2(resheads, "STATUS", line);
        }
        if(code > 0){
          int clen = 0;
          bool chunked = false;
          while(ttsockgets(sock, line, SOCKLINEBUFSIZ) && *line != '\0'){
            tcstrsqzspc(line);
            char *pv = strchr(line, ':');
            if(!pv) continue;
            *(pv++) = '\0';
            while(*pv == ' '){
              pv++;
            }
            tcstrtolower(line);
            if(!strcmp(line, "content-length")){
              clen = tcatoi(pv);
            } else if(!strcmp(line, "transfer-encoding")){
              if(!tcstricmp(pv, "chunked")) chunked = true;
            }
            if(resheads) tcmapput2(resheads, line, pv);
          }
          if(!ttsockcheckend(sock) && resbody){
            bool err = false;
            char *body;
            int bsiz;
            if(code == 304){
              body = tcmemdup("", 0);
              bsiz = 0;
            } else if(chunked){
              int asiz = SOCKLINEBUFSIZ;
              body = tcmalloc(asiz);
              bsiz = 0;
              while(true){
                pthread_cleanup_push(free, body);
                if(!ttsockgets(sock, line, SOCKLINEBUFSIZ)) err = true;
                pthread_cleanup_pop(0);
                if(err || *line == '\0') break;
                int size = tcatoih(line);
                if(bsiz + size > HTTPBODYMAXSIZ){
                  err = true;
                  break;
                }
                if(bsiz + size > asiz){
                  asiz = bsiz * 2 + size;
                  body = tcrealloc(body, asiz);
                }
                pthread_cleanup_push(free, body);
                if(size > 0) ttsockrecv(sock, body + bsiz, size);
                if(ttsockgetc(sock) != '\r' || ttsockgetc(sock) != '\n') err = true;
                pthread_cleanup_pop(0);
                if(err || size < 1) break;
                bsiz += size;
              }
            } else if(clen > 0){
              if(clen > HTTPBODYMAXSIZ){
                body = tcmemdup("", 0);
                bsiz = 0;
                err = true;
              } else {
                body = tcmalloc(clen);
                bsiz = 0;
                pthread_cleanup_push(free, body);
                if(ttsockrecv(sock, body, clen)){
                  bsiz = clen;
                } else {
                  err = true;
                }
                pthread_cleanup_pop(0);
              }
            } else {
              int asiz = SOCKLINEBUFSIZ;
              body = tcmalloc(asiz);
              bsiz = 0;
              while(true){
                int c;
                pthread_cleanup_push(free, body);
                c = ttsockgetc(sock);
                pthread_cleanup_pop(0);
                if(c == -1) break;
                if(bsiz >= HTTPBODYMAXSIZ){
                  err = true;
                  break;
                }
                if(bsiz >= asiz){
                  asiz = bsiz * 2;
                  body = tcrealloc(body, asiz);
                }
                body[bsiz++] = c;
              }
            }
            if(err){
              code = -1;
            } else if(resbody){
              tcxstrcat(resbody, body, bsiz);
            }
            tcfree(body);
          }
        }
      }
      pthread_cleanup_pop(1);
      pthread_cleanup_pop(1);
      pthread_cleanup_pop(1);
    }
  }
  pthread_cleanup_pop(1);
  return code;
}


/* Serialize a real number. */
void ttpackdouble(double num, char *buf){
  assert(buf);
  double dinteg, dfract;
  dfract = modf(num, &dinteg);
  int64_t linteg, lfract;
  if(isnormal(dinteg) || dinteg == 0){
    linteg = dinteg;
    lfract = dfract * TRILLIONNUM;
  } else if(isinf(dinteg)){
    linteg = dinteg > 0 ? INT64_MAX : INT64_MIN;
    lfract = 0;
  } else {
    linteg = INT64_MIN;
    lfract = INT64_MIN;
  }
  linteg = TTHTONLL(linteg);
  memcpy(buf, &linteg, sizeof(linteg));
  lfract = TTHTONLL(lfract);
  memcpy(buf + sizeof(linteg), &lfract, sizeof(lfract));
}


/* Redintegrate a serialized real number. */
double ttunpackdouble(const char *buf){
  assert(buf);
  int64_t linteg, lfract;
  memcpy(&linteg, buf, sizeof(linteg));
  linteg = TTNTOHLL(linteg);
  memcpy(&lfract, buf + sizeof(linteg), sizeof(lfract));
  lfract = TTNTOHLL(lfract);
  if(lfract == INT64_MIN && linteg == INT64_MIN){
    return NAN;
  } else if(linteg == INT64_MAX){
    return INFINITY;
  } else if(linteg == INT64_MIN){
    return -INFINITY;
  }
  return linteg + (double)lfract / TRILLIONNUM;
}



/*************************************************************************************************
 * server utilities
 *************************************************************************************************/


#define TTADDRBUFSIZ   1024              // size of an address buffer
#define TTDEFTHNUM     5                 // default number of threads
#define TTEVENTMAX     256               // maximum number of events
#define TTWAITREQUEST  0.2               // waiting seconds for requests
#define TTWAITWORKER   0.1               // waiting seconds for finish of workers


/* private function prototypes */
static void *ttservtimer(void *argp);
static void ttservtask(TTSOCK *sock, TTREQ *req);
static void *ttservdeqtasks(void *argp);


/* Create a server object. */
TTSERV *ttservnew(void){
  TTSERV *serv = tcmalloc(sizeof(*serv));
  serv->host[0] = '\0';
  serv->addr[0] = '\0';
  serv->port = 0;
  serv->queue = tclistnew();
  if(pthread_mutex_init(&serv->qmtx, NULL) != 0) tcmyfatal("pthread_mutex_init failed");
  if(pthread_cond_init(&serv->qcnd, NULL) != 0) tcmyfatal("pthread_cond_init failed");
  if(pthread_mutex_init(&serv->tmtx, NULL) != 0) tcmyfatal("pthread_mutex_init failed");
  if(pthread_cond_init(&serv->tcnd, NULL) != 0) tcmyfatal("pthread_cond_init failed");
  serv->thnum = TTDEFTHNUM;
  serv->timeout = 0;
  serv->term = false;
  serv->do_log = NULL;
  serv->opq_log = NULL;
  serv->timernum = 0;
  serv->do_task = NULL;
  serv->opq_task = NULL;
  serv->do_term = NULL;
  serv->opq_term = NULL;
  return serv;
}


/* Delete a server object. */
void ttservdel(TTSERV *serv){
  assert(serv);
  pthread_cond_destroy(&serv->tcnd);
  pthread_mutex_destroy(&serv->tmtx);
  pthread_cond_destroy(&serv->qcnd);
  pthread_mutex_destroy(&serv->qmtx);
  tclistdel(serv->queue);
  tcfree(serv);
}


/* Configure a server object. */
bool ttservconf(TTSERV *serv, const char *host, int port){
  assert(serv);
  bool err = false;
  if(port < 1){
    if(!host || host[0] == '\0'){
      err = true;
      serv->addr[0] = '\0';
      ttservlog(serv, TTLOGERROR, "invalid socket path");
    }
  } else {
    if(host && !ttgethostaddr(host, serv->addr)){
      err = true;
      serv->addr[0] = '\0';
      ttservlog(serv, TTLOGERROR, "ttgethostaddr failed");
    }
  }
  snprintf(serv->host, sizeof(serv->host), "%s", host ? host : "");
  serv->port = port;
  return !err;
}


/* Set tuning parameters of a server object. */
void ttservtune(TTSERV *serv, int thnum, double timeout){
  assert(serv && thnum > 0);
  serv->thnum = thnum;
  serv->timeout = timeout;
}


/* Set the logging handler of a server object. */
void ttservsetloghandler(TTSERV *serv, void (*do_log)(int, const char *, void *), void *opq){
  assert(serv && do_log);
  serv->do_log = do_log;
  serv->opq_log = opq;
}


/* Add a timed handler to a server object. */
void ttservaddtimedhandler(TTSERV *serv, double freq, void (*do_timed)(void *), void *opq){
  assert(serv && freq >= 0.0 && do_timed);
  if(serv->timernum >= TTTIMERMAX - 1) return;
  TTTIMER *timer = serv->timers + serv->timernum;
  timer->freq_timed = freq;
  timer->do_timed = do_timed;
  timer->opq_timed = opq;
  serv->timernum++;
}


/* Set the response handler of a server object. */
void ttservsettaskhandler(TTSERV *serv, void (*do_task)(TTSOCK *, void *, TTREQ *), void *opq){
  assert(serv && do_task);
  serv->do_task = do_task;
  serv->opq_task = opq;
}


/* Set the termination handler of a server object. */
void ttservsettermhandler(TTSERV *serv, void (*do_term)(void *), void *opq){
  assert(serv && do_term);
  serv->do_term = do_term;
  serv->opq_term = opq;
}


/* Start the service of a server object. */
bool ttservstart(TTSERV *serv){
  assert(serv);
  int lfd;
  if(serv->port < 1){
    lfd = ttopenservsockunix(serv->host);
    if(lfd == -1){
      ttservlog(serv, TTLOGERROR, "ttopenservsockunix failed");
      return false;
    }
  } else {
    lfd = ttopenservsock(serv->addr[0] != '\0' ? serv->addr : NULL, serv->port);
    if(lfd == -1){
      ttservlog(serv, TTLOGERROR, "ttopenservsock failed");
      return false;
    }
  }
  int epfd = epoll_create(TTEVENTMAX);
  if(epfd == -1){
    close(lfd);
    ttservlog(serv, TTLOGERROR, "epoll_create failed");
    return false;
  }
  ttservlog(serv, TTLOGSYSTEM, "service started: %d", getpid());
  bool err = false;
  for(int i = 0; i < serv->timernum; i++){
    TTTIMER *timer = serv->timers + i;
    timer->alive = false;
    timer->serv = serv;
    if(pthread_create(&(timer->thid), NULL, ttservtimer, timer) == 0){
      ttservlog(serv, TTLOGINFO, "timer thread %d started", i + 1);
      timer->alive = true;
    } else {
      ttservlog(serv, TTLOGERROR, "pthread_create (ttservtimer) failed");
      err = true;
    }
  }
  int thnum = serv->thnum;
  TTREQ reqs[thnum];
  for(int i = 0; i < thnum; i++){
    reqs[i].alive = true;
    reqs[i].serv = serv;
    reqs[i].epfd = epfd;
    reqs[i].mtime = tctime();
    reqs[i].keep = false;
    reqs[i].idx = i;
    if(pthread_create(&reqs[i].thid, NULL, ttservdeqtasks, reqs + i) == 0){
      ttservlog(serv, TTLOGINFO, "worker thread %d started", i + 1);
    } else {
      reqs[i].alive = false;
      err = true;
      ttservlog(serv, TTLOGERROR, "pthread_create (ttservdeqtasks) failed");
    }
  }
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events = EPOLLIN;
  ev.data.fd = lfd;
  if(epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &ev) != 0){
    err = true;
    ttservlog(serv, TTLOGERROR, "epoll_ctl failed");
  }
  ttservlog(serv, TTLOGSYSTEM, "listening started");
  while(!serv->term){
    struct epoll_event events[TTEVENTMAX];
    int fdnum = epoll_wait(epfd, events, TTEVENTMAX, TTWAITREQUEST * 1000);
    if(fdnum != -1){
      for(int i = 0; i < fdnum; i++){
        if(events[i].data.fd == lfd){
          char addr[TTADDRBUFSIZ];
          int port;
          int cfd;
          if(serv->port < 1){
            cfd = ttacceptsockunix(lfd);
            sprintf(addr, "(unix)");
            port = 0;
          } else {
            cfd = ttacceptsock(serv,lfd, addr, &port);
          }
          if(epoll_reassoc(epfd, lfd) != 0){
            if(cfd != -1) close(cfd);
            cfd = -1;
          }
          if(cfd != -1){
            ttservlog(serv, TTLOGINFO, "connected: %s:%d", addr, port);
            struct epoll_event ev;
            memset(&ev, 0, sizeof(ev));
            ev.events = EPOLLIN | EPOLLONESHOT;
            ev.data.fd = cfd;
            if(epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ev) != 0){
              close(cfd);
              err = true;
              ttservlog(serv, TTLOGERROR, "epoll_ctl failed");
            }
          } else {
            err = true;
            ttservlog(serv, TTLOGERROR, "ttacceptsock failed");
            if(epoll_ctl(epfd, EPOLL_CTL_DEL, lfd, NULL) != 0)
              ttservlog(serv, TTLOGERROR, "epoll_ctl failed");
            if(close(lfd) != 0) ttservlog(serv, TTLOGERROR, "close failed");
            tcsleep(TTWAITWORKER);
            if(serv->port < 1){
              lfd = ttopenservsockunix(serv->host);
              if(lfd == -1) ttservlog(serv, TTLOGERROR, "ttopenservsockunix failed");
            } else {
              lfd = ttopenservsock(serv->addr[0] != '\0' ? serv->addr : NULL, serv->port);
              if(lfd == -1) ttservlog(serv, TTLOGERROR, "ttopenservsock failed");
            }
            if(lfd >= 0){
              memset(&ev, 0, sizeof(ev));
              ev.events = EPOLLIN;
              ev.data.fd = lfd;
              if(epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &ev) == 0){
                ttservlog(serv, TTLOGSYSTEM, "listening restarted");
              } else {
                ttservlog(serv, TTLOGERROR, "epoll_ctl failed");
              }
            }
          }
        } else {
          int cfd = events[i].data.fd;
          if(pthread_mutex_lock(&serv->qmtx) == 0){
            tclistpush(serv->queue, &cfd, sizeof(cfd));
            if(pthread_mutex_unlock(&serv->qmtx) != 0){
              err = true;
              ttservlog(serv, TTLOGERROR, "pthread_mutex_unlock failed");
            }
            if(pthread_cond_signal(&serv->qcnd) != 0){
              err = true;
              ttservlog(serv, TTLOGERROR, "pthread_cond_signal failed");
            }
          } else {
            err = true;
            ttservlog(serv, TTLOGERROR, "pthread_mutex_lock failed");
          }
        }
      }
    } else {
      if(errno == EINTR){
        ttservlog(serv, TTLOGINFO, "signal interruption");
      } else {
        err = true;
        ttservlog(serv, TTLOGERROR, "epoll_wait failed");
      }
    }
    if(serv->timeout > 0){
      double ctime = tctime();
      for(int i = 0; i < thnum; i++){
        double itime = ctime - reqs[i].mtime;
        if(itime > serv->timeout + TTWAITREQUEST + SOCKRCVTIMEO + SOCKSNDTIMEO &&
           pthread_cancel(reqs[i].thid) == 0){
          ttservlog(serv, TTLOGINFO, "worker thread %d canceled by timeout", i + 1);
          void *rv;
          if(pthread_join(reqs[i].thid, &rv) == 0){
            if(rv && rv != PTHREAD_CANCELED) err = true;
            reqs[i].mtime = tctime();
            if(pthread_create(&reqs[i].thid, NULL, ttservdeqtasks, reqs + i) != 0){
              reqs[i].alive = false;
              err = true;
              ttservlog(serv, TTLOGERROR, "pthread_create (ttservdeqtasks) failed");
            } else {
              ttservlog(serv, TTLOGINFO, "worker thread %d started", i + 1);
            }
          } else {
            reqs[i].alive = false;
            err = true;
            ttservlog(serv, TTLOGERROR, "pthread_join failed");
          }
        }
      }
    }
  }
  ttservlog(serv, TTLOGSYSTEM, "listening finished");
  if(pthread_cond_broadcast(&serv->qcnd) != 0){
    err = true;
    ttservlog(serv, TTLOGERROR, "pthread_cond_broadcast failed");
  }
  if(pthread_cond_broadcast(&serv->tcnd) != 0){
    err = true;
    ttservlog(serv, TTLOGERROR, "pthread_cond_broadcast failed");
  }
  tcsleep(TTWAITWORKER);
  if(serv->do_term) serv->do_term(serv->opq_term);
  for(int i = 0; i < thnum; i++){
    if(!reqs[i].alive) continue;
    if(pthread_cancel(reqs[i].thid) == 0)
      ttservlog(serv, TTLOGINFO, "worker thread %d was canceled", i + 1);
    void *rv;
    if(pthread_join(reqs[i].thid, &rv) == 0){
      ttservlog(serv, TTLOGINFO, "worker thread %d finished", i + 1);
      if(rv && rv != PTHREAD_CANCELED) err = true;
    } else {
      err = true;
      ttservlog(serv, TTLOGERROR, "pthread_join failed");
    }
  }
  if(tclistnum(serv->queue) > 0)
    ttservlog(serv, TTLOGINFO, "%d requests discarded", tclistnum(serv->queue));
  tclistclear(serv->queue);
  for(int i = 0; i < serv->timernum; i++){
    TTTIMER *timer = serv->timers + i;
    if(!timer->alive) continue;
    void *rv;
    if(pthread_cancel(timer->thid) == 0)
      ttservlog(serv, TTLOGINFO, "timer thread %d was canceled", i + 1);
    if(pthread_join(timer->thid, &rv) == 0){
      ttservlog(serv, TTLOGINFO, "timer thread %d finished", i + 1);
      if(rv && rv != PTHREAD_CANCELED) err = true;
    } else {
      err = true;
      ttservlog(serv, TTLOGERROR, "pthread_join failed");
    }
  }
  if(epoll_close(epfd) != 0){
    err = true;
    ttservlog(serv, TTLOGERROR, "epoll_close failed");
  }
  if(serv->port < 1 && unlink(serv->host) == -1){
    err = true;
    ttservlog(serv, TTLOGERROR, "unlink failed");
  }
  if(lfd >= 0 && close(lfd) != 0){
    err = true;
    ttservlog(serv, TTLOGERROR, "close failed");
  }
  ttservlog(serv, TTLOGSYSTEM, "service finished");
  serv->term = false;
  return !err;
}


/* Send the terminate signal to a server object. */
bool ttservkill(TTSERV *serv){
  assert(serv);
  serv->term = true;
  return true;
}


/* Call the logging function of a server object. */
void ttservlog(TTSERV *serv, int level, const char *format, ...){
  assert(serv && format);
  if(!serv->do_log) return;
  char buf[TTIOBUFSIZ];
  va_list ap;
  va_start(ap, format);
  vsnprintf(buf, TTIOBUFSIZ, format, ap);
  va_end(ap);
  serv->do_log(level, buf, serv->opq_log);
}


/* Check whether a server object is killed. */
bool ttserviskilled(TTSERV *serv){
  assert(serv);
  return serv->term;
}


/* Break a simple server expression. */
char *ttbreakservexpr(const char *expr, int *pp){
  assert(expr);
  char *host = tcstrdup(expr);
  char *pv = strchr(host, '#');
  if(pv) *pv = '\0';
  int port = -1;
  pv = strchr(host, ':');
  if(pv){
    *(pv++) = '\0';
    if(*pv >= '0' && *pv <= '9') port = tcatoi(pv);
  }
  if(port < 0) port = TTDEFPORT;
  if(pp) *pp = port;
  tcstrtrim(host);
  if(*host == '\0'){
    tcfree(host);
    host = tcstrdup("127.0.0.1");
  }
  return host;
}


/* Call the timed function of a server object.
   `argp' specifies the argument structure of the server object.
   The return value is `NULL' on success and other on failure. */
static void *ttservtimer(void *argp){
  TTTIMER *timer = argp;
  TTSERV *serv = timer->serv;
  bool err = false;
  if(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) != 0){
    err = true;
    ttservlog(serv, TTLOGERROR, "pthread_setcancelstate failed");
  }
  tcsleep(TTWAITWORKER);
  double freqi;
  double freqd = modf(timer->freq_timed, &freqi);
  while(!serv->term){
    if(pthread_mutex_lock(&serv->tmtx) == 0){
      struct timeval tv;
      struct timespec ts;
      if(gettimeofday(&tv, NULL) == 0){
        ts.tv_sec = tv.tv_sec + (int)freqi;
        ts.tv_nsec = tv.tv_usec * 1000.0 + freqd * 1000000000.0;
        if(ts.tv_nsec >= 1000000000){
          ts.tv_nsec -= 1000000000;
          ts.tv_sec++;
        }
      } else {
        ts.tv_sec = (1ULL << (sizeof(time_t) * 8 - 1)) - 1;
        ts.tv_nsec = 0;
      }
      int code = pthread_cond_timedwait(&serv->tcnd, &serv->tmtx, &ts);
      if(code == 0 || code == ETIMEDOUT || code == EINTR){
        if(pthread_mutex_unlock(&serv->tmtx) != 0){
          err = true;
          ttservlog(serv, TTLOGERROR, "pthread_mutex_unlock failed");
          break;
        }
        if(code != 0 && !serv->term) timer->do_timed(timer->opq_timed);
      } else {
        pthread_mutex_unlock(&serv->tmtx);
        err = true;
        ttservlog(serv, TTLOGERROR, "pthread_cond_timedwait failed");
      }
    } else {
      err = true;
      ttservlog(serv, TTLOGERROR, "pthread_mutex_lock failed");
    }
  }
  return err ? "error" : NULL;
}


/* Call the task function of a server object.
   `req' specifies the request object.
   `sock' specifies the socket object. */
static void ttservtask(TTSOCK *sock, TTREQ *req){
  TTSERV *serv = req->serv;
  if(!serv->do_task) return;
  serv->do_task(sock, serv->opq_task, req);
}


/* Dequeue tasks of a server object and dispatch them.
   `argp' specifies the argument structure of the server object.
   The return value is `NULL' on success and other on failure. */
static void *ttservdeqtasks(void *argp){
  TTREQ *req = argp;
  TTSERV *serv = req->serv;
  bool err = false;
  if(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) != 0){
    err = true;
    ttservlog(serv, TTLOGERROR, "pthread_setcancelstate failed");
  }
  sigset_t sigset;
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGPIPE);
  sigset_t oldsigset;
  sigemptyset(&sigset);
  if(pthread_sigmask(SIG_BLOCK, &sigset, &oldsigset) != 0){
    err = true;
    ttservlog(serv, TTLOGERROR, "pthread_sigmask failed");
  }
  bool empty = false;
  while(!serv->term){
    if(pthread_mutex_lock(&serv->qmtx) == 0){
      struct timeval tv;
      struct timespec ts;
      if(gettimeofday(&tv, NULL) == 0){
        ts.tv_sec = tv.tv_sec;
        ts.tv_nsec = tv.tv_usec * 1000.0 + TTWAITREQUEST * 1000000000.0;
        if(ts.tv_nsec >= 1000000000){
          ts.tv_nsec -= 1000000000;
          ts.tv_sec++;
        }
      } else {
        ts.tv_sec = (1ULL << (sizeof(time_t) * 8 - 1)) - 1;
        ts.tv_nsec = 0;
      }
      int code = empty ? pthread_cond_timedwait(&serv->qcnd, &serv->qmtx, &ts) : 0;
      if(code == 0 || code == ETIMEDOUT || code == EINTR){
        void *val = tclistshift2(serv->queue);
        if(pthread_mutex_unlock(&serv->qmtx) != 0){
          err = true;
          ttservlog(serv, TTLOGERROR, "pthread_mutex_unlock failed");
        }
        if(val){
          empty = false;
          int cfd = *(int *)val;
          tcfree(val);
          pthread_cleanup_push((void (*)(void *))close, (void *)(intptr_t)cfd);
          TTSOCK *sock = ttsocknew(cfd);
          pthread_cleanup_push((void (*)(void *))ttsockdel, sock);
          bool reuse;
          do {
            if(serv->timeout > 0) ttsocksetlife(sock, serv->timeout);
            req->mtime = tctime();
            req->keep = false;
            ttservtask(sock, req);
            reuse = false;
            if(sock->end){
              req->keep = false;
            } else if(sock->ep > sock->rp){
              reuse = true;
            }
          } while(reuse);
          pthread_cleanup_pop(1);
          pthread_cleanup_pop(0);
          if(req->keep){
            struct epoll_event ev;
            memset(&ev, 0, sizeof(ev));
            ev.events = EPOLLIN | EPOLLONESHOT;
            ev.data.fd = cfd;
            if(epoll_ctl(req->epfd, EPOLL_CTL_MOD, cfd, &ev) != 0){
              close(cfd);
              err = true;
              ttservlog(serv, TTLOGERROR, "epoll_ctl failed");
            }
          } else {
            if(epoll_ctl(req->epfd, EPOLL_CTL_DEL, cfd, NULL) != 0){
              err = true;
              ttservlog(serv, TTLOGERROR, "epoll_ctl failed");
            }
            if(!ttclosesock(cfd)){
              err = true;
              ttservlog(serv, TTLOGERROR, "close failed");
            }
            ttservlog(serv, TTLOGINFO, "connection finished");
          }
        } else {
          empty = true;
        }
      } else {
        pthread_mutex_unlock(&serv->qmtx);
        err = true;
        ttservlog(serv, TTLOGERROR, "pthread_cond_timedwait failed");
      }
    } else {
      err = true;
      ttservlog(serv, TTLOGERROR, "pthread_mutex_lock failed");
    }
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_testcancel();
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    req->mtime = tctime();
  }
  if(pthread_sigmask(SIG_SETMASK, &oldsigset, NULL) != 0){
    err = true;
    ttservlog(serv, TTLOGERROR, "pthread_sigmask failed");
  }
  return err ? "error" : NULL;
}



/*************************************************************************************************
 * features for experts
 *************************************************************************************************/


#define NULLDEV        "/dev/null"       // path of the null device


/* Switch the process into the background. */
bool ttdaemonize(void){
  fflush(stdout);
  fflush(stderr);
  switch(fork()){
    case -1: return false;
    case 0: break;
    default: _exit(0);
  }
  if(setsid() == -1) return false;
  switch(fork()){
    case -1: return false;
    case 0: break;
    default: _exit(0);
  }
  umask(0);
  if(chdir(MYPATHSTR) == -1) return false;
  close(0);
  close(1);
  close(2);
  int fd = open(NULLDEV, O_RDWR, 0);
  if(fd != -1){
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    if(fd > 2) close(fd);
  }
  return true;
}


/* Get the load average of the system. */
double ttgetloadavg(void){
  double avgs[3];
  int anum = getloadavg(avgs, sizeof(avgs) / sizeof(*avgs));
  if(anum < 1) return 0.0;
  return anum == 1 ? avgs[0] : avgs[1];
}


/* Convert a string to a time stamp. */
uint64_t ttstrtots(const char *str){
  assert(str);
  if(!tcstricmp(str, "now")) str = "-1";
  int64_t ts = tcatoi(str);
  if(ts < 0) ts = tctime() * 1000000;
  return ts;
}


/* Get the command name of a command ID number. */
const char *ttcmdidtostr(int id){
  switch(id){
    case TTCMDPUT: return "put";
    case TTCMDPUTKEEP: return "putkeep";
    case TTCMDPUTCAT: return "putcat";
    case TTCMDPUTSHL: return "putshl";
    case TTCMDPUTNR: return "putnr";
    case TTCMDOUT: return "out";
    case TTCMDGET: return "get";
    case TTCMDMGET: return "mget";
    case TTCMDVSIZ: return "vsiz";
    case TTCMDITERINIT: return "iterinit";
    case TTCMDITERNEXT: return "iternext";
    case TTCMDFWMKEYS: return "fwmkeys";
    case TTCMDADDINT: return "addint";
    case TTCMDADDDOUBLE: return "adddouble";
    case TTCMDEXT: return "ext";
    case TTCMDSYNC: return "sync";
    case TTCMDOPTIMIZE: return "optimize";
    case TTCMDVANISH: return "vanish";
    case TTCMDCOPY: return "copy";
    case TTCMDRESTORE: return "restore";
    case TTCMDSETMST: return "setmst";
    case TTCMDRNUM: return "rnum";
    case TTCMDSIZE: return "size";
    case TTCMDSTAT: return "stat";
    case TTCMDMISC: return "misc";
    case TTCMDREPL: return "repl";
  }
  return "(unknown)";
}



// END OF FILE
