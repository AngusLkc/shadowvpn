#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "shadowvpn.h"

static vpn_ctx_t vpn_ctx;

static void sig_handler(int signo) {
  if (signo == SIGINT)
    exit(1);
  else
    vpn_stop(&vpn_ctx);
}

int main(int argc, char **argv) {
  shadowvpn_args_t args;
  if (0 != args_parse(&args, argc, argv)) {
    errf("error when parsing args");
    return EXIT_FAILURE;
  }
  if (args.cmd == SHADOWVPN_CMD_START) {
    if (0 != daemon_start(&args)) {
      errf("can not start daemon");
      return EXIT_FAILURE;
    }
  } else if (args.cmd == SHADOWVPN_CMD_STOP) {
    if (0 != daemon_stop(&args)) {
      errf("can not stop daemon");
      return EXIT_FAILURE;
    }
    return 0;
  } else if (args.cmd == SHADOWVPN_CMD_RESTART) {
    if (0 != daemon_stop(&args)) {
      errf("can not stop daemon");
      return EXIT_FAILURE;
    }
    if (0 != daemon_start(&args)) {
      errf("can not start daemon");
      return EXIT_FAILURE;
    }
  }
  if (0 != crypto_init()) {
    errf("shadowvpn_crypto_init");
    return EXIT_FAILURE;
  }
  if (0 !=crypto_set_password(args.password, strlen(args.password))) {
    errf("can not set password");
    return EXIT_FAILURE;
  }
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);
  if (-1 == vpn_ctx_init(&vpn_ctx, &args)) {
    return EXIT_FAILURE;
  }
  return vpn_run(&vpn_ctx);
}
