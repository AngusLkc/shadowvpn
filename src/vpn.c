#include "shadowvpn.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_tun.h>

#define tun_read(...) read(__VA_ARGS__)
#define tun_write(...) write(__VA_ARGS__)

//初始化tun适配器
int vpn_tun_alloc(const char *dev) {
	struct ifreq ifr;
	int fd, e;
	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		err("open");
		errf("can not open /dev/net/tun");
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	if(*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if ((e = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
		err("ioctl[TUNSETIFF]");
		errf("can not setup tun device: %s", dev);
		close(fd);
		return -1;
	}
	return fd;
}

//初始化UDP_SOCKET
int vpn_udp_alloc(int if_bind, const char *host, int port, struct sockaddr *addr, socklen_t* addrlen) {
	struct addrinfo hints;
	struct addrinfo *res;
	int sock, r, flags;
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	if (0 != (r = getaddrinfo(host, NULL, &hints, &res))) {
		errf("getaddrinfo: %s", gai_strerror(r));
		return -1;
	}
	if (res->ai_family == AF_INET)
		((struct sockaddr_in *)res->ai_addr)->sin_port = htons(port);
	else if (res->ai_family == AF_INET6)
		((struct sockaddr_in6 *)res->ai_addr)->sin6_port = htons(port);
	else {
		errf("unknown ai_family %d", res->ai_family);
		freeaddrinfo(res);
		return -1;
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	*addrlen = res->ai_addrlen;
	if (-1 == (sock = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP))) {
		err("socket");
		errf("can not create socket");
		freeaddrinfo(res);
		return -1;
	}
	if (if_bind) {
		if (0 != bind(sock, res->ai_addr, res->ai_addrlen)) {
			err("bind");
			errf("can not bind %s:%d", host, port);
			close(sock);
			freeaddrinfo(res);
			return -1;
		}
	}
	freeaddrinfo(res);
	flags = fcntl(sock, F_GETFL, 0);
	if (flags != -1) {
		if (-1 != fcntl(sock, F_SETFL, flags | O_NONBLOCK))
			return sock;
	}
	err("fcntl");
	close(sock);
	return -1;
}

static int max(int a, int b) {
	return a > b ? a : b;
}

//初始化VPN句柄上下文,客户端与服务端均需要调用
int vpn_ctx_init(vpn_ctx_t *ctx, shadowvpn_args_t *args) {
	int i;
	bzero(ctx, sizeof(vpn_ctx_t));
	ctx->remote_addrp = (struct sockaddr *)&ctx->remote_addr;
	if (-1 == pipe(ctx->control_pipe)) {
		err("pipe");
		return -1;
	}
	if (-1 == (ctx->tun = vpn_tun_alloc(args->intf))) {
		errf("failed to create tun device");
		return -1;
	}
	ctx->nsock = 1;
	ctx->socks = calloc(ctx->nsock, sizeof(int));
	for (i = 0; i < ctx->nsock; i++) {
		int *sock = ctx->socks + i;
		if (-1 == (*sock = vpn_udp_alloc(args->mode == SHADOWVPN_MODE_SERVER, args->server, args->port, ctx->remote_addrp, &ctx->remote_addrlen))) {
			errf("failed to create UDP socket");
			close(ctx->tun);
			return -1;
		}
	}
	ctx->args = args;
	return 0;
}

int vpn_run(vpn_ctx_t *ctx) {
	fd_set readset;
	int max_fd = 0, i;
	ssize_t r;
	size_t usertoken_len = 0;
	if (ctx->running) {
		errf("can not start, already running");
		return -1;
	}
	ctx->running = 1;
	shell_up(ctx->args);
	if (ctx->args->user_tokens_len) {
		usertoken_len = SHADOWVPN_USERTOKEN_LEN; //8
	}
	ctx->tun_buf = malloc(ctx->args->mtu + SHADOWVPN_ZERO_BYTES + usertoken_len); //32 + 8
	ctx->udp_buf = malloc(ctx->args->mtu + SHADOWVPN_ZERO_BYTES + usertoken_len);
	bzero(ctx->tun_buf, SHADOWVPN_ZERO_BYTES);
	bzero(ctx->udp_buf, SHADOWVPN_ZERO_BYTES);
	if (ctx->args->mode == SHADOWVPN_MODE_SERVER && usertoken_len) {
		ctx->nat_ctx = malloc(sizeof(nat_ctx_t));
		nat_init(ctx->nat_ctx, ctx->args);
	}
	logf("VPN started");
	while (ctx->running) {
		FD_ZERO(&readset);
		FD_SET(ctx->control_pipe[0], &readset);
		FD_SET(ctx->tun, &readset);
		max_fd = 0;
		for (i = 0; i < ctx->nsock; i++) {
			FD_SET(ctx->socks[i], &readset);
			max_fd = max(max_fd, ctx->socks[i]);
		}
		max_fd = max(ctx->tun, max_fd) + 1;
		if (-1 == select(max_fd, &readset, NULL, NULL, NULL)) {
			if (errno == EINTR)
				continue; //信号中断
			err("select");
			break;
		}
		if (FD_ISSET(ctx->control_pipe[0], &readset)) {
			char pipe_buf;
			(void)read(ctx->control_pipe[0], &pipe_buf, 1);
			break;
		}
		//处理tun适配器可读事件
		if (FD_ISSET(ctx->tun, &readset)) {
			r = tun_read(ctx->tun, ctx->tun_buf + SHADOWVPN_ZERO_BYTES + usertoken_len, ctx->args->mtu);
			if (r == -1) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					// do nothing
				} else if (errno == EPERM || errno == EINTR) {
					err("read from tun");
				} else {
					err("read from tun");
					break;
				}
			}
			if (usertoken_len) {
				if (ctx->args->mode == SHADOWVPN_MODE_CLIENT) {
					//如果运行在客户端模式,则在数据头部加上usertoken
					memcpy(ctx->tun_buf + SHADOWVPN_ZERO_BYTES, ctx->args->user_tokens[0], usertoken_len);
				} else {
					//如果运行在服务端模式,则进行反向SNAT地址转换并重新计算校验和
					nat_fix_downstream(ctx->nat_ctx, ctx->tun_buf + SHADOWVPN_ZERO_BYTES, r + usertoken_len, ctx->remote_addrp, &ctx->remote_addrlen);
				}
			}
			//不管是运行在客户端还是服务端模式,从tun适配器读取到数据均需要加密后发送到对端
			if (ctx->remote_addrlen) {
				crypto_encrypt(ctx->udp_buf, ctx->tun_buf, r + usertoken_len);
				int sock_to_send = ctx->socks[0];
				r = sendto(sock_to_send, ctx->udp_buf + SHADOWVPN_PACKET_OFFSET, SHADOWVPN_OVERHEAD_LEN + usertoken_len + r, 0, ctx->remote_addrp, ctx->remote_addrlen);
				if (r == -1) {
					if (errno == EAGAIN || errno == EWOULDBLOCK) {
						// do nothing
					} else if (errno == ENETUNREACH || errno == ENETDOWN || errno == EPERM || errno == EINTR || errno == EMSGSIZE) {
						err("sendto");
					} else {
						err("sendto");
						break;
					}
				}
			}
		}
		//处理socket可读事件,从socket读取的数据需要解密后写入tun适配器
		for (i = 0; i < ctx->nsock; i++) {
			int sock = ctx->socks[i];
			if (FD_ISSET(sock, &readset)) {
				struct sockaddr_storage temp_remote_addr;
				socklen_t temp_remote_addrlen = sizeof(temp_remote_addr);
				r = recvfrom(sock, ctx->udp_buf + SHADOWVPN_PACKET_OFFSET, SHADOWVPN_OVERHEAD_LEN + usertoken_len + ctx->args->mtu, 0, (struct sockaddr *)&temp_remote_addr, &temp_remote_addrlen);
				if (r == -1) {
					if (errno == EAGAIN || errno == EWOULDBLOCK) {
						// do nothing
					} else if (errno == ENETUNREACH || errno == ENETDOWN || errno == EPERM || errno == EINTR) {
						err("recvfrom");
					} else {
						err("recvfrom");
						break;
					}
				}
				if (r == 0)
					continue;
				if (-1 == crypto_decrypt(ctx->tun_buf, ctx->udp_buf, r - SHADOWVPN_OVERHEAD_LEN)) {
					errf("dropping invalid packet, maybe wrong password");
				} else {
					if (ctx->args->mode == SHADOWVPN_MODE_SERVER) {
						memcpy(ctx->remote_addrp, &temp_remote_addr, temp_remote_addrlen);
						ctx->remote_addrlen = temp_remote_addrlen;
					}
					if (usertoken_len) {
						if (ctx->args->mode == SHADOWVPN_MODE_SERVER)
							if (-1 == nat_fix_upstream(ctx->nat_ctx, ctx->tun_buf + SHADOWVPN_ZERO_BYTES, r - SHADOWVPN_OVERHEAD_LEN, ctx->remote_addrp, ctx->remote_addrlen))
								continue;
					}
					if (-1 == tun_write(ctx->tun, ctx->tun_buf + SHADOWVPN_ZERO_BYTES + usertoken_len, r - SHADOWVPN_OVERHEAD_LEN - usertoken_len)) {
						if (errno == EAGAIN || errno == EWOULDBLOCK) {
							// do nothing
						} else if (errno == EPERM || errno == EINTR || errno == EINVAL) {
							err("write to tun");
						} else {
							err("write to tun");
							break;
						}
					}
				}
			}
		}
	}
	free(ctx->tun_buf);
	free(ctx->udp_buf);
	shell_down(ctx->args);
	close(ctx->tun);
	for (i = 0; i < ctx->nsock; i++)
		close(ctx->socks[i]);
	ctx->running = 0;
	return -1;
}

int vpn_stop(vpn_ctx_t *ctx) {
	logf("shutting down by user");
	if (!ctx->running) {
		errf("can not stop, not running");
		return -1;
	}
	ctx->running = 0;
	char buf = 0;
	if (-1 == write(ctx->control_pipe[1], &buf, 1)) {
		err("write");
		return -1;
	}
	return 0;
}
