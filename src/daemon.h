#ifndef DAEMON_H
#define DAEMON_H

#include "args.h"

int daemon_start(const shadowvpn_args_t *args);

int daemon_stop(const shadowvpn_args_t *args);

#endif
