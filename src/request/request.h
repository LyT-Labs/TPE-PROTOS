#ifndef REQUEST_H
#define REQUEST_H

#include <stdbool.h>
#include <stdint.h>
#include "../helpers/buffer.h"
#include "../helpers/parser.h"

enum request_state {
    REQUEST_VERSION = 0,
    REQUEST_CMD,
    REQUEST_RSV,
    REQUEST_ATYP,
    REQUEST_ADDRLEN,
    REQUEST_DSTADDR,
    REQUEST_DSTPORT,
    REQUEST_DONE,
    REQUEST_ERROR,
};

struct request_parser {
    struct parser *parser;
    enum request_state state;
    uint8_t ver;
    uint8_t cmd;
    uint8_t atyp;

    uint8_t addr[256];   // Para IPv4, IPv6 o FQDN
    uint16_t port;
    uint8_t port_len;      // cantidad de bytes leídos del puerto

    uint8_t addr_len;    // cantidad de bytes leídos para el address
    uint8_t expected_len; // tamaño esperado del address

    bool has_addr_len;    // para ATYP = domain (FQDN)
};

void request_parser_init(struct request_parser *p);
enum request_state request_consume(buffer *b, struct request_parser *p, bool *errored);
bool request_is_done(enum request_state st, bool *errored);
int request_marshall_reply(buffer *b, uint8_t rep, uint8_t atyp, const uint8_t *addr, uint16_t port);
void request_close(struct request_parser *p);

#endif
