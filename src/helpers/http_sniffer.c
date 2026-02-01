#include "http_sniffer.h"
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdio.h>

static const char base64_table[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t base64_decode(const char *input, char *output, size_t max_len) {
    size_t in_len = strlen(input);
    size_t out_pos = 0;
    
    for (size_t i = 0; i < in_len && out_pos < max_len - 1; ) {
        int val1 = -1, val2 = -1, val3 = -1, val4 = -1;
        
        while (i < in_len && (val1 = base64_decode_char(input[i])) == -1) i++;
        if (i >= in_len) break;
        i++;
        
        while (i < in_len && (val2 = base64_decode_char(input[i])) == -1) i++;
        if (i >= in_len) break;
        i++;
        
        if (i < in_len) {
            val3 = base64_decode_char(input[i]);
            if (val3 != -1) i++;
        }
        
        if (i < in_len) {
            val4 = base64_decode_char(input[i]);
            if (val4 != -1) i++;
        }
        
        if (val1 != -1 && val2 != -1) {
            output[out_pos++] = (val1 << 2) | (val2 >> 4);
            
            if (val3 != -1 && out_pos < max_len - 1) {
                output[out_pos++] = ((val2 & 0x0F) << 4) | (val3 >> 2);
                
                if (val4 != -1 && out_pos < max_len - 1) {
                    output[out_pos++] = ((val3 & 0x03) << 6) | val4;
                }
            }
        }
    }
    
    output[out_pos] = '\0';
    return out_pos;
}

void http_sniffer_init(struct http_sniffer *sniffer) {
    sniffer->username[0] = '\0';
    sniffer->password[0] = '\0';
    sniffer->line_buffer[0] = '\0';
    sniffer->line_len = 0;
    sniffer->credentials_captured = false;
    sniffer->in_headers = true;
}

static void process_header_line(struct http_sniffer *sniffer, const char *line) {
    if (sniffer->credentials_captured) {
        return;
    }

    if (line[0] == '\0') {
        sniffer->in_headers = false;
        return;
    }

    if (strncasecmp(line, "Authorization: Basic ", 21) == 0) {
        const char *base64_creds = line + 21;
        
        while (*base64_creds == ' ') base64_creds++;
        
        char decoded[512];
        base64_decode(base64_creds, decoded, sizeof(decoded));
        
        char *colon = strchr(decoded, ':');
        if (colon != NULL) {
            size_t user_len = colon - decoded;
            if (user_len >= HTTP_MAX_USER) {
                user_len = HTTP_MAX_USER - 1;
            }
            memcpy(sniffer->username, decoded, user_len);
            sniffer->username[user_len] = '\0';
            
            size_t pass_len = strlen(colon + 1);
            if (pass_len >= HTTP_MAX_PASS) {
                pass_len = HTTP_MAX_PASS - 1;
            }
            memcpy(sniffer->password, colon + 1, pass_len);
            sniffer->password[pass_len] = '\0';
            
            sniffer->credentials_captured = true;
        }
    }
}

bool http_sniffer_process(struct http_sniffer *sniffer,
                           const uint8_t *data,
                           size_t len) {
    if (sniffer->credentials_captured || !sniffer->in_headers) {
        return sniffer->credentials_captured;
    }

    for (size_t i = 0; i < len; i++) {
        char c = (char)data[i];
        
        if (c == '\n') {
            sniffer->line_buffer[sniffer->line_len] = '\0';
            process_header_line(sniffer, sniffer->line_buffer);
            sniffer->line_len = 0;
            
            if (sniffer->credentials_captured || !sniffer->in_headers) {
                return sniffer->credentials_captured;
            }
        } else if (c != '\r') {
            if (sniffer->line_len < HTTP_MAX_LINE - 1) {
                sniffer->line_buffer[sniffer->line_len++] = c;
            } else {
                sniffer->line_len = 0;
            }
        }
    }
    
    return false;
}

bool http_sniffer_has_credentials(const struct http_sniffer *sniffer) {
    return sniffer->credentials_captured;
}

void http_sniffer_get_credentials(const struct http_sniffer *sniffer,
                                   char *user_out,
                                   char *pass_out) {
    strcpy(user_out, sniffer->username);
    strcpy(pass_out, sniffer->password);
}

void http_sniffer_reset(struct http_sniffer *sniffer) {
    http_sniffer_init(sniffer);
}
