#ifndef HTTP_SNIFFER_H
#define HTTP_SNIFFER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define HTTP_MAX_LINE 2048
#define HTTP_MAX_USER 256
#define HTTP_MAX_PASS 256

struct http_sniffer {
    char username[HTTP_MAX_USER];
    char password[HTTP_MAX_PASS];
    char line_buffer[HTTP_MAX_LINE];
    size_t line_len;
    bool credentials_captured;
    bool in_headers;
};

void http_sniffer_init(struct http_sniffer *sniffer);

bool http_sniffer_process(struct http_sniffer *sniffer,
                           const uint8_t *data,
                           size_t len);

bool http_sniffer_has_credentials(const struct http_sniffer *sniffer);

void http_sniffer_get_credentials(const struct http_sniffer *sniffer,
                                   char *user_out,
                                   char *pass_out);

void http_sniffer_reset(struct http_sniffer *sniffer);

#endif
