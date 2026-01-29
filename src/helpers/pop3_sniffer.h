#ifndef POP3_SNIFFER_H
#define POP3_SNIFFER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define POP3_MAX_LINE 512
#define POP3_MAX_USER 256
#define POP3_MAX_PASS 256

enum pop3_state {
    POP3_WAITING_USER,
    POP3_WAITING_PASS,
    POP3_CREDENTIALS_CAPTURED
};

struct pop3_sniffer {
    enum pop3_state state;
    char username[POP3_MAX_USER];
    char password[POP3_MAX_PASS];
    char line_buffer[POP3_MAX_LINE];
    size_t line_len;
};

void pop3_sniffer_init(struct pop3_sniffer *sniffer);

bool pop3_sniffer_process(struct pop3_sniffer *sniffer, 
                           const uint8_t *data, 
                           size_t len);

bool pop3_sniffer_has_credentials(const struct pop3_sniffer *sniffer);

void pop3_sniffer_get_credentials(const struct pop3_sniffer *sniffer,
                                   char *user_out,
                                   char *pass_out);

void pop3_sniffer_reset(struct pop3_sniffer *sniffer);

#endif
