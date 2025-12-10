#ifndef MONITOR_H
#define MONITOR_H

#include "selector.h"

int monitor_init(fd_selector s, const char *addr, const char *port);

const struct fd_handler * monitor_get_handler(void);

#endif
