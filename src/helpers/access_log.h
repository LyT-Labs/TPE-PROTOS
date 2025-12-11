#ifndef ACCESS_LOG_H
#define ACCESS_LOG_H

#include <stdint.h>
#include <stdbool.h>

void access_log_record(const char *username, const char *src_ip, const char *dst_host, uint16_t dst_port, bool success);

#endif
