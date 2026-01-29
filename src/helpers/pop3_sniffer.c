#include "pop3_sniffer.h"
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdio.h>

void pop3_sniffer_init(struct pop3_sniffer *sniffer) {
    sniffer->state = POP3_WAITING_USER;
    sniffer->username[0] = '\0';
    sniffer->password[0] = '\0';
    sniffer->line_buffer[0] = '\0';
    sniffer->line_len = 0;
}

static void process_line(struct pop3_sniffer *sniffer, const char *line) {
    if (sniffer->state == POP3_CREDENTIALS_CAPTURED) {
        return;
    }

    if (strncasecmp(line, "USER ", 5) == 0) {
        const char *username = line + 5;
        while (*username == ' ') username++;
        
        size_t len = 0;
        while (username[len] && username[len] != '\r' && 
               username[len] != '\n' && len < POP3_MAX_USER - 1) {
            len++;
        }
        
        memcpy(sniffer->username, username, len);
        sniffer->username[len] = '\0';
        sniffer->state = POP3_WAITING_PASS;
        
    } else if (sniffer->state == POP3_WAITING_PASS && 
               strncasecmp(line, "PASS ", 5) == 0) {
        const char *password = line + 5;
        while (*password == ' ') password++;
        
        size_t len = 0;
        while (password[len] && password[len] != '\r' && 
               password[len] != '\n' && len < POP3_MAX_PASS - 1) {
            len++;
        }
        
        memcpy(sniffer->password, password, len);
        sniffer->password[len] = '\0';
        sniffer->state = POP3_CREDENTIALS_CAPTURED;
    }
}

bool pop3_sniffer_process(struct pop3_sniffer *sniffer, 
                           const uint8_t *data, 
                           size_t len) {
    if (sniffer->state == POP3_CREDENTIALS_CAPTURED) {
        return true;
    }

    for (size_t i = 0; i < len; i++) {
        char c = (char)data[i];
        
        if (c == '\n') {
            sniffer->line_buffer[sniffer->line_len] = '\0';
            process_line(sniffer, sniffer->line_buffer);
            sniffer->line_len = 0;
            
            if (sniffer->state == POP3_CREDENTIALS_CAPTURED) {
                return true;
            }
        } else if (c != '\r') {
            if (sniffer->line_len < POP3_MAX_LINE - 1) {
                sniffer->line_buffer[sniffer->line_len++] = c;
            } else {
                sniffer->line_len = 0;
            }
        }
    }
    
    return false;
}

bool pop3_sniffer_has_credentials(const struct pop3_sniffer *sniffer) {
    return sniffer->state == POP3_CREDENTIALS_CAPTURED;
}

void pop3_sniffer_get_credentials(const struct pop3_sniffer *sniffer,
                                   char *user_out,
                                   char *pass_out) {
    strcpy(user_out, sniffer->username);
    strcpy(pass_out, sniffer->password);
}

void pop3_sniffer_reset(struct pop3_sniffer *sniffer) {
    pop3_sniffer_init(sniffer);
}
