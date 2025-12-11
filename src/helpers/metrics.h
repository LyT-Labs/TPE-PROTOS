#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>

struct socks5_metrics {
    uint64_t total_connections;
    uint64_t current_connections;
    uint64_t max_concurrent_connections;

    uint64_t bytes_client_to_origin;
    uint64_t bytes_origin_to_client;

    uint64_t auth_ok;
    uint64_t auth_fail;

    uint64_t dns_ok;
    uint64_t dns_fail;

    uint64_t rep_code_count[256];    // contador por código REP (0x00..0xFF)
};

struct socks5_metrics * metrics_get(void);

void metrics_reset(void);

#endif
