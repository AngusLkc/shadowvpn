#include <stdlib.h>
#include <stdio.h>
#include "shadowvpn.h"
#include "shell.h"

static int shell_run(shadowvpn_args_t *args, int is_up);

int shell_up(shadowvpn_args_t *args) {
  return shell_run(args, 1);
}

int shell_down(shadowvpn_args_t *args) {
  return shell_run(args, 0);
}

static int shell_run(shadowvpn_args_t *args, int is_up) {
  const char *script;
  char *buf;
  int r;
  if (is_up) {
    script = args->up_script;
  } else {
    script = args->down_script;
  }
  if (script == NULL || script[0] == 0) {
    errf("warning: script not set");
    return 0;
  }
  buf = malloc(strlen(script) + 8);
  sprintf(buf, "sh %s", script);
  logf("executing %s", script);
  if (0 != (r = system(buf))) {
    free(buf);
    errf("script %s returned non-zero return code: %d", script, r);
    return -1;
  }
  free(buf);
  return 0;
}
