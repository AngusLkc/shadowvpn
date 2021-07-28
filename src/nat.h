#ifndef NAT_H
#define NAT_H

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "uthash.h"

typedef struct {
  struct sockaddr_storage addr;
  socklen_t addrlen;
} addr_info_t;

typedef struct {
  int id;
  char user_token[SHADOWVPN_USERTOKEN_LEN];
  addr_info_t source_addr;
  uint32_t input_tun_ip;
  uint32_t output_tun_ip;
  UT_hash_handle hh1;
  UT_hash_handle hh2;
} client_info_t;

typedef struct {
  client_info_t *token_to_clients;
  client_info_t *ip_to_clients;
} nat_ctx_t;

int nat_init(nat_ctx_t *ctx, shadowvpn_args_t *args);
int nat_fix_upstream(nat_ctx_t *ctx, unsigned char *buf, size_t buflen, const struct sockaddr *addr, socklen_t addrlen);
int nat_fix_downstream(nat_ctx_t *ctx, unsigned char *buf, size_t buflen, struct sockaddr *addr, socklen_t *addrlen);

#endif
