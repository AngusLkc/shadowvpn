#include "shadowvpn.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "portable_endian.h"

#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * 初始化NAT地址转换上下文,预先给每个客户端分配一个虚拟IP
 * 从客户端接收的IP帧源地址都要转换成这个虚拟IP,然后再写入tun适配器
 * 从tun适配器读取的IP帧目标地址都需要转换成源地址转换前的来源地址
 */
int nat_init(nat_ctx_t *ctx, shadowvpn_args_t *args) {
  int i;
  bzero(ctx, sizeof(nat_ctx_t));
  for (i = 0; i < args->user_tokens_len; i++) {
    client_info_t *client = malloc(sizeof(client_info_t));
    bzero(client, sizeof(client_info_t));
    memcpy(client->user_token, args->user_tokens[i], SHADOWVPN_USERTOKEN_LEN);
    client->output_tun_ip = htonl(args->netip + i + 1);
    struct in_addr in;
    in.s_addr = client->output_tun_ip;
    logf("assigning %s to user %16llx", inet_ntoa(in), htobe64(*((uint64_t *)args->user_tokens[i])));
    HASH_ADD(hh1, ctx->token_to_clients, user_token, SHADOWVPN_USERTOKEN_LEN, client);
    HASH_ADD(hh2, ctx->ip_to_clients, output_tun_ip, 4, client);
  }
  return 0;
}

typedef struct {
  uint8_t ver;
  uint8_t tos;
  uint16_t total_len;
  uint16_t id;
  uint16_t frag;
  uint8_t ttl;
  uint8_t proto;
  uint16_t checksum;
  uint32_t saddr;
  uint32_t daddr;
} ipv4_hdr_t;

typedef struct {
  uint16_t sport;
  uint16_t dport;
  uint32_t seq;
  uint32_t ack;
  uint32_t not_interested;
  uint16_t checksum;
  uint16_t upt;
} tcp_hdr_t;

typedef struct {
  uint16_t sport;
  uint16_t dport;
  uint16_t len;
  uint16_t checksum;
} udp_hdr_t;

// from openvpn
#define ADJUST_CHECKSUM(acc, cksum) { \
  int _acc = acc; \
  _acc += (cksum); \
  if (_acc < 0) { \
    _acc = -_acc; \
    _acc = (_acc >> 16) + (_acc & 0xffff); \
    _acc += _acc >> 16; \
    (cksum) = (uint16_t) ~_acc; \
  } else { \
    _acc = (_acc >> 16) + (_acc & 0xffff); \
    _acc += _acc >> 16; \
    (cksum) = (uint16_t) _acc; \
  } \
}

/*
 * 服务端角色:
 * 从socket读取到客户端发来的IP帧时调用,保存源地址以供反向SNAT修复时替换目标地址使用
 * 服务端为每个客户端分配了个虚拟IP地址,客户端发来的IP帧源地址统一替换成这个地址并修复IP/TCP/UDP校验和
 */
int nat_fix_upstream(nat_ctx_t *ctx, unsigned char *buf, size_t buflen, const struct sockaddr *addr, socklen_t addrlen) {
  uint8_t iphdr_len;
  if (buflen < SHADOWVPN_USERTOKEN_LEN + 20) {
    errf("nat: ip packet too short");
    return -1;
  }
  ipv4_hdr_t *iphdr = (ipv4_hdr_t *)(buf + SHADOWVPN_USERTOKEN_LEN);
  if ((iphdr->ver & 0xf0) != 0x40) {
    return 0;
  }
  iphdr_len = (iphdr->ver & 0x0f) * 4;
  //在哈希表里查找为这个客户端分配的client_info_t结构,
  //因为服务端为每个客户端分配了个虚拟IP地址保存在client_info_t结构里,
  //所以需要对从socket收到的客户端发来的IP帧进行源地址转换后再写入到tun适配器,
  client_info_t *client = NULL;
  HASH_FIND(hh1, ctx->token_to_clients, buf, SHADOWVPN_USERTOKEN_LEN, client);
  if (client == NULL) {
    errf("nat: client not found for given user token");
    return -1;
  }
  //保存从socket接收数据的源地址
  client->source_addr.addrlen =  addrlen;
  memcpy(&client->source_addr.addr, addr, addrlen);
  //保存skb中的源地址
  int32_t acc = 0;
  client->input_tun_ip = iphdr->saddr;
  //替换skb中的源地址为分配的虚拟IP地址
  iphdr->saddr = client->output_tun_ip;
  //计算32位地址差值并重新计算校验和
  acc = client->input_tun_ip - iphdr->saddr;//源地址转换校验和差值=skb原来的地址-skb替换后地址
  ADJUST_CHECKSUM(acc, iphdr->checksum);
  //如果未分片或是第一个分片,需要更新TCP/UDP校验和
  if (0 == (iphdr->frag & htons(0x1fff))) {
    void *ip_payload = buf + SHADOWVPN_USERTOKEN_LEN + iphdr_len;
    if (iphdr->proto == IPPROTO_TCP) {
      if (buflen < iphdr_len + 20) {
        errf("nat: tcp packet too short");
        return -1;
      }
      tcp_hdr_t *tcphdr = ip_payload;
      ADJUST_CHECKSUM(acc, tcphdr->checksum);
    } else if (iphdr->proto == IPPROTO_UDP) {
      if (buflen < iphdr_len + 8) {
        errf("nat: udp packet too short");
        return -1;
      }
      udp_hdr_t *udphdr = ip_payload;
      ADJUST_CHECKSUM(acc, udphdr->checksum);
    }
  }
  return 0;
}

/*
 * 服务端角色:
 * 从tun适配器读取到IP帧时调用,
 * 由于对客户端发来的IP帧进行了SNAT地址转换,
 * 所以从tun适配器读取到的IP帧发给客户端前需要进行反向SNAT修复
 */
int nat_fix_downstream(nat_ctx_t *ctx, unsigned char *buf, size_t buflen, struct sockaddr *addr, socklen_t *addrlen) {
  uint8_t iphdr_len;
  if (buflen < SHADOWVPN_USERTOKEN_LEN + 20) {
    errf("nat: ip packet too short");
    return -1;
  }
  ipv4_hdr_t *iphdr = (ipv4_hdr_t *)(buf + SHADOWVPN_USERTOKEN_LEN);
  if ((iphdr->ver & 0xf0) != 0x40) { //IPv4
    return 0;
  }
  iphdr_len = (iphdr->ver & 0x0f) * 4; //头部长度
  client_info_t *client = NULL;
  HASH_FIND(hh2, ctx->ip_to_clients, &iphdr->daddr, 4, client); //查找映射前的地址
  if (client == NULL) {
    errf("nat: client not found for given user ip");
    return -1;
  }
  //替换skb目标地址(反向SNAT修复)
  *addrlen = client->source_addr.addrlen;
  memcpy(addr, &client->source_addr.addr, *addrlen);
  memcpy(buf, client->user_token, SHADOWVPN_USERTOKEN_LEN);
  //替换skb中的目标地址并重新计算IP校验和
  int32_t acc = 0;
  acc = iphdr->daddr - client->input_tun_ip;//目标地址转换校验和差值=skb原来的地址-skb替换后地址
  iphdr->daddr = client->input_tun_ip;
  ADJUST_CHECKSUM(acc, iphdr->checksum);
  //如果未分片或是第一个分片,需要更新TCP/UDP校验和
  if (0 == (iphdr->frag & htons(0x1fff))) {
    void *ip_payload = buf + SHADOWVPN_USERTOKEN_LEN + iphdr_len;
    if (iphdr->proto == IPPROTO_TCP) {
      if (buflen < iphdr_len + 20) {
        errf("nat: tcp packet too short");
        return -1;
      }
      tcp_hdr_t *tcphdr = ip_payload;
      ADJUST_CHECKSUM(acc, tcphdr->checksum);
    } else if (iphdr->proto == IPPROTO_UDP) {
      if (buflen < iphdr_len + 8) {
        errf("nat: udp packet too short");
        return -1;
      }
      udp_hdr_t *udphdr = ip_payload;
      ADJUST_CHECKSUM(acc, udphdr->checksum);
    }
  }
  return 0;
}
