#ifndef VPN_H
#define VPN_H

#include <time.h>

#include "args.h"
#include "nat.h"

typedef struct {
  int running;
  int nsock;
  int *socks;
  int tun;
  int control_pipe[2];
  unsigned char *tun_buf;
  unsigned char *udp_buf;
  struct sockaddr_storage remote_addr;
  struct sockaddr *remote_addrp;
  socklen_t remote_addrlen;
  shadowvpn_args_t *args;
  nat_ctx_t *nat_ctx;
} vpn_ctx_t;

int vpn_ctx_init(vpn_ctx_t *ctx, shadowvpn_args_t *args);
int vpn_run(vpn_ctx_t *ctx);
int vpn_stop(vpn_ctx_t *ctx);

int vpn_tun_alloc(const char *dev);
int vpn_udp_alloc(int if_bind, const char *host, int port, struct sockaddr *addr, socklen_t* addrlen);

#endif
