#ifndef CREDENTIALS_LOG_H
#define CREDENTIALS_LOG_H

#include <stdint.h>
#include <stdbool.h>

void credentials_log_record(const char *protocol,
                             const char *src_ip,
                             const char *dst_host,
                             uint16_t dst_port,
                             const char *username,
                             const char *password);

#endif
