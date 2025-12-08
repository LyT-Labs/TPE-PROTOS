#ifndef ECHO_SERVER_H
#define ECHO_SERVER_H

#include <stdint.h>
#include "../helpers/selector.h"
#include "../helpers/buffer.h"
#include "../socks5/socks5.h"

int echo_server_main(int argc, char *argv[]);

#endif
